#ifndef AppVersion
  #error AppVersion must be supplied with /DAppVersion=x.y.z
#endif
#ifndef NumericVersion
  #error NumericVersion must be supplied with /DNumericVersion=x.y.z.0
#endif
#ifndef SourceDir
  #error SourceDir must point at the extracted, version-locked NEOTH bundle
#endif
#ifndef OutputDir
  #define OutputDir "."
#endif
#ifndef TargetArch
  #define TargetArch "x64"
#endif

#define AppIdValue "TheGeekFreaks.NEOTH.BF6060F4-B75D-4E9A-BEB6-7EC8CB94A3C1"
#define UninstallKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\" + AppIdValue + "_is1"
#define InstallerStateKey "Software\The Geek Freaks\NEOTH\Installer"

[Setup]
AppId={#AppIdValue}
AppName=NEOTH
AppVersion={#AppVersion}
AppVerName=NEOTH {#AppVersion}
AppPublisher=The Geek Freaks
AppPublisherURL=https://github.com/The-Geek-Freaks/NEOTH
AppSupportURL=https://github.com/The-Geek-Freaks/NEOTH/issues
AppUpdatesURL=https://github.com/The-Geek-Freaks/NEOTH/releases
AppCopyright=Copyright (c) The Geek Freaks contributors
VersionInfoVersion={#NumericVersion}
VersionInfoCompany=The Geek Freaks
VersionInfoDescription=NEOTH installer
VersionInfoProductName=NEOTH
VersionInfoProductVersion={#NumericVersion}
VersionInfoProductTextVersion={#AppVersion}
VersionInfoTextVersion={#AppVersion}
DefaultDirName={autopf}\NEOTH
DefaultGroupName=NEOTH
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
MinVersion=10.0.19041
OutputDir={#OutputDir}
OutputBaseFilename=NEOTH-{#AppVersion}-{#TargetArch}-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
WizardResizable=yes
SetupLogging=yes
CloseApplications=yes
CloseApplicationsFilter=neoth.exe,neothd.exe,neothd-gui.exe,neoth-migrate.exe,neoth-relay.exe,neoth-keet-bridge.exe
RestartApplications=no
SetupMutex=NEOTH-BF6060F4-B75D-4E9A-BEB6-7EC8CB94A3C1-Setup
Uninstallable=yes
UninstallDisplayName=NEOTH {#AppVersion}
UninstallDisplayIcon={app}\neothd-gui.exe
UsePreviousAppDir=yes
UsePreviousGroup=yes
ChangesEnvironment=yes
LicenseFile={#SourceDir}\LICENSE-MIT
InfoBeforeFile={#SourceDir}\README.md

#if TargetArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible and not arm64
ArchitecturesInstallIn64BitMode=x64compatible
#endif

#ifdef SignedBuild
SignTool=neoth
SignedUninstaller=yes
SignToolRetryCount=3
SignToolRetryDelay=1000
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\neoth.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\neothd.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\neothd-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\neoth-migrate.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\neoth-relay.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\neoth-keet-bridge.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\freedom.yaml.example"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\import-manifest.example.yaml"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE-MIT"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE-APACHE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\THIRD_PARTY_LICENSES"; DestDir: "{app}"; Flags: ignoreversion
; The snapshot is intentionally never overlaid onto the live directory. The
; manifest is the final Files entry so its callback runs once, inside Inno's
; rollback-capable install phase, after the complete stage was extracted.
Source: "{#SourceDir}\self-knowledge\*"; DestDir: "{app}\.neoth-self-knowledge-stage"; Excludes: "manifest.json"; Flags: ignoreversion recursesubdirs createallsubdirs uninsneveruninstall
Source: "{#SourceDir}\self-knowledge\manifest.json"; DestDir: "{app}\.neoth-self-knowledge-stage"; Flags: ignoreversion uninsneveruninstall; AfterInstall: PrepareSelfKnowledgeTransaction

[UninstallDelete]
; These are package-owned paths. The successful install path removes all three
; hidden transaction paths; the entries also cover interrupted installations.
Type: filesandordirs; Name: "{app}\self-knowledge"
Type: filesandordirs; Name: "{app}\.neoth-self-knowledge-stage"
Type: filesandordirs; Name: "{app}\.neoth-self-knowledge-backup"
Type: files; Name: "{app}\.neoth-self-knowledge-committed"
Type: files; Name: "{app}\.neoth-self-knowledge-committed.tmp"

[Icons]
Name: "{group}\NEOTH"; Filename: "{app}\neothd-gui.exe"; Parameters: "--product-launcher"; WorkingDir: "{app}"; Comment: "Open NEOTH"
Name: "{group}\NEOTH CLI"; Filename: "{cmd}"; Parameters: "/D /K ""set NEOTH_INTERFACE=&& ""{app}\neoth.exe"" interface set cli && ""{app}\neoth.exe"""""; WorkingDir: "{app}"; Comment: "Switch to and open the NEOTH command line"
Name: "{group}\NEOTH GUI"; Filename: "{app}\neothd-gui.exe"; WorkingDir: "{app}"; Comment: "Open the NEOTH graphical interface"
Name: "{group}\NEOTH Documentation"; Filename: "{app}\README.md"
Name: "{group}\Uninstall NEOTH"; Filename: "{uninstallexe}"
Name: "{autodesktop}\NEOTH"; Filename: "{app}\neothd-gui.exe"; Parameters: "--product-launcher"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\neothd-gui.exe"; Parameters: "--product-launcher"; Description: "Launch NEOTH"; Flags: nowait postinstall skipifsilent

[Code]
var
  UninstallOwnsPathEntry: Boolean;
  UninstallOwnedPath: String;
  SelfKnowledgeSwapActive: Boolean;
  SelfKnowledgeHadPrevious: Boolean;
  SelfKnowledgeCommitted: Boolean;

function WindowsGetFileAttributes(FileName: String): Cardinal;
  external 'GetFileAttributesW@kernel32.dll stdcall';

function SelfKnowledgeLivePath: String;
begin
  Result := ExpandConstant('{app}\self-knowledge');
end;

function SelfKnowledgeStagePath: String;
begin
  Result := ExpandConstant('{app}\.neoth-self-knowledge-stage');
end;

function SelfKnowledgeBackupPath: String;
begin
  Result := ExpandConstant('{app}\.neoth-self-knowledge-backup');
end;

function SelfKnowledgeCommitMarkerPath: String;
begin
  Result := ExpandConstant('{app}\.neoth-self-knowledge-committed');
end;

function PathIsReparsePoint(Path: String): Boolean;
var
  Attributes: Cardinal;
begin
  Attributes := WindowsGetFileAttributes(Path);
  Result := (Attributes <> $FFFFFFFF) and ((Attributes and $400) <> 0);
end;

procedure RequireRegularDirectory(Path, Description: String);
begin
  if FileExists(Path) then
    RaiseException(Description + ' is a file, not a directory: ' + Path);
  if DirExists(Path) and PathIsReparsePoint(Path) then
    RaiseException(Description + ' must not be a junction or symbolic link: ' + Path);
end;

procedure RequireRegularFile(Path, Description: String);
begin
  if DirExists(Path) then
    RaiseException(Description + ' is a directory, not a file: ' + Path);
  if FileExists(Path) and PathIsReparsePoint(Path) then
    RaiseException(Description + ' must not be a symbolic link: ' + Path);
end;

procedure RequireRegularTree(Path, Description: String);
var
  FindRec: TFindRec;
  ChildPath: String;
begin
  RequireRegularDirectory(Path, Description);
  if not DirExists(Path) then
    Exit;
  if FindFirst(AddBackslash(Path) + '*', FindRec) then begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then begin
          ChildPath := AddBackslash(Path) + FindRec.Name;
          if PathIsReparsePoint(ChildPath) then
            RaiseException(
              Description + ' contains a junction or symbolic link: ' + ChildPath);
          if (FindRec.Attributes and $10) <> 0 then
            RequireRegularTree(ChildPath, Description);
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

procedure DeleteOwnedDirectory(Path, Description: String);
begin
  RequireRegularTree(Path, Description);
  if DirExists(Path) and not DelTree(Path, True, True, True) then
    RaiseException('Could not remove ' + Description + ': ' + Path);
end;

procedure DeleteOwnedFile(Path, Description: String);
begin
  RequireRegularFile(Path, Description);
  if FileExists(Path) and not DeleteFile(Path) then
    RaiseException('Could not remove ' + Description + ': ' + Path);
end;

function VerifyNewSelfKnowledgeSnapshot(SnapshotPath: String): Boolean;
var
  Index, ResultCode: Integer;
begin
  Result := False;
  { Release smoke uses this failpoint to prove that an AfterInstall verification
    failure restores N while Inno is still able to roll all N+1 files back. }
  for Index := 1 to ParamCount do begin
    if CompareText(ParamStr(Index), '/TESTSELFKNOWLEDGEVERIFYFAIL') = 0 then begin
      Log('Self-knowledge verification failpoint requested by installer smoke.');
      Result := False;
      Exit;
    end;
  end;
  if not FileExists(ExpandConstant('{app}\neoth.exe')) or
     not FileExists(SnapshotPath + '\manifest.json') then
    Exit;
  if not Exec(
       ExpandConstant('{app}\neoth.exe'),
       '--output json self-knowledge verify --snapshot ' + AddQuotes(SnapshotPath),
       ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Exit;
  Result := ResultCode = 0;
end;

function PowerShellDoubleQuotedLiteral(Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '`', '``', True);
  StringChangeEx(Result, '$', '`$', True);
  StringChangeEx(Result, '"', '`"', True);
  Result := '"' + Result + '"';
end;

function ExistingCandidateHasMatchingAuthenticode(CandidatePath: String): Boolean;
var
  PowerShellPath, Command: String;
  ResultCode: Integer;
begin
  Result := False;
  RequireRegularFile(CandidatePath, 'installed NEOTH recovery executable');
  if not FileExists(CandidatePath) then
    Exit;
  PowerShellPath := ExpandConstant(
    '{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Command :=
    '$ErrorActionPreference=[System.Management.Automation.ActionPreference]::Stop;' +
    '$p=[Security.Principal.WindowsPrincipal]::new(' +
    '[Security.Principal.WindowsIdentity]::GetCurrent());' +
    'if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))' +
    '{exit 52};' +
    '$a=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath ' +
      PowerShellDoubleQuotedLiteral(CandidatePath) + ';' +
    '$b=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath ' +
      PowerShellDoubleQuotedLiteral(ExpandConstant('{srcexe}')) + ';' +
    '$v=[System.Management.Automation.SignatureStatus]::Valid;' +
    'if($a.Status -ne $v -or $b.Status -ne $v -or ' +
    '$null -eq $a.SignerCertificate -or $null -eq $b.SignerCertificate -or ' +
    '$a.SignerCertificate.Subject -cne $b.SignerCertificate.Subject){exit 53};';
  if not ExecAsOriginalUser(
       PowerShellPath,
       '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' +
         Command,
       ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Exit;
  Result := ResultCode = 0;
end;

function VerifyInstalledSelfKnowledgeSnapshot(SnapshotPath: String): Boolean;
var
  CandidatePath: String;
  ResultCode: Integer;
begin
  CandidatePath := ExpandConstant('{app}\neoth.exe');
  Result := False;
  if not ExistingCandidateHasMatchingAuthenticode(CandidatePath) then
    Exit;
  if not FileExists(SnapshotPath + '\manifest.json') then
    Exit;
  if not ExecAsOriginalUser(
       CandidatePath,
       '--output json self-knowledge verify --snapshot ' + AddQuotes(SnapshotPath),
       ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Exit;
  Result := ResultCode = 0;
end;

procedure RollbackSelfKnowledgeTransaction;
var
  LivePath, StagePath, BackupPath, MarkerPath: String;
begin
  if not SelfKnowledgeSwapActive then
    Exit;
  LivePath := SelfKnowledgeLivePath;
  StagePath := SelfKnowledgeStagePath;
  BackupPath := SelfKnowledgeBackupPath;
  MarkerPath := SelfKnowledgeCommitMarkerPath;

  DeleteOwnedDirectory(LivePath, 'uncommitted NEOTH self-knowledge snapshot');
  if SelfKnowledgeHadPrevious and DirExists(BackupPath) then begin
    if not RenameFile(BackupPath, LivePath) then
      RaiseException('Could not roll back the previous NEOTH self-knowledge snapshot.');
  end;
  DeleteOwnedDirectory(StagePath, 'NEOTH self-knowledge transaction stage');
  DeleteOwnedFile(MarkerPath, 'NEOTH self-knowledge commit marker');
  DeleteOwnedFile(MarkerPath + '.tmp', 'NEOTH self-knowledge temporary commit marker');
  SelfKnowledgeSwapActive := False;
end;

procedure PrepareSelfKnowledgeTransaction;
var
  LivePath, StagePath, BackupPath, MarkerPath, MarkerTempPath: String;
begin
  LivePath := SelfKnowledgeLivePath;
  StagePath := SelfKnowledgeStagePath;
  BackupPath := SelfKnowledgeBackupPath;
  MarkerPath := SelfKnowledgeCommitMarkerPath;
  MarkerTempPath := MarkerPath + '.tmp';

  RequireRegularTree(LivePath, 'NEOTH self-knowledge snapshot');
  RequireRegularTree(StagePath, 'NEOTH self-knowledge transaction stage');
  RequireRegularTree(BackupPath, 'NEOTH self-knowledge transaction backup');
  if not DirExists(StagePath) or
     not FileExists(StagePath + '\manifest.json') then
    RaiseException('Installer self-knowledge transaction stage is incomplete.');
  if DirExists(BackupPath) then
    RaiseException('A previous NEOTH self-knowledge transaction was not recovered.');
  RequireRegularFile(MarkerPath, 'NEOTH self-knowledge commit marker');
  RequireRegularFile(MarkerTempPath, 'NEOTH self-knowledge transaction marker');
  if FileExists(MarkerPath) or FileExists(MarkerTempPath) then
    RaiseException('A previous NEOTH self-knowledge transaction marker was not recovered.');
  if not SaveStringToFile(MarkerTempPath, '{#AppVersion}', False) then
    RaiseException('Could not persist the NEOTH self-knowledge transaction state.');

  SelfKnowledgeHadPrevious := DirExists(LivePath);
  if SelfKnowledgeHadPrevious and not RenameFile(LivePath, BackupPath) then begin
    DeleteOwnedFile(MarkerTempPath, 'NEOTH self-knowledge transaction marker');
    RaiseException('Could not stage the previous NEOTH self-knowledge snapshot for rollback.');
  end;
  SelfKnowledgeSwapActive := True;
  if not RenameFile(StagePath, LivePath) then begin
    if SelfKnowledgeHadPrevious and DirExists(BackupPath) then
      RenameFile(BackupPath, LivePath);
    DeleteOwnedFile(MarkerTempPath, 'NEOTH self-knowledge transaction marker');
    SelfKnowledgeSwapActive := False;
    RaiseException('Could not atomically activate the new NEOTH self-knowledge snapshot.');
  end;
  if not VerifyNewSelfKnowledgeSnapshot(LivePath) then begin
    RollbackSelfKnowledgeTransaction;
    RaiseException(
      'The installed executable rejected its self-knowledge snapshot; the previous snapshot was restored.');
  end;
end;

procedure CommitSelfKnowledgeTransaction;
var
  BackupPath, MarkerPath, MarkerTempPath: String;
begin
  BackupPath := SelfKnowledgeBackupPath;
  MarkerPath := SelfKnowledgeCommitMarkerPath;
  MarkerTempPath := MarkerPath + '.tmp';
  { ssPostInstall is Inno's rollback cutoff. From this point forward the new
    binaries and their already verified N+1 snapshot stay together; cleanup
    errors must never restore N under N+1 binaries. }
  SelfKnowledgeCommitted := True;
  SelfKnowledgeSwapActive := False;
  if FileExists(MarkerTempPath) and not RenameFile(MarkerTempPath, MarkerPath) then
    Log('Warning: could not publish the NEOTH self-knowledge commit marker.');
  { The marker makes cleanup retryable if deletion is interrupted. A normal
    successful install nevertheless leaves no backup or transaction metadata. }
  try
    DeleteOwnedDirectory(BackupPath, 'previous NEOTH self-knowledge snapshot');
    DeleteOwnedFile(MarkerPath, 'NEOTH self-knowledge commit marker');
    DeleteOwnedFile(MarkerTempPath, 'NEOTH self-knowledge transaction marker');
  except
    { The live tree is already verified and durably marked committed. Keep it
      live and let the next installer retry package-owned backup cleanup. }
    Log('Warning: committed NEOTH self-knowledge cleanup was deferred: ' +
      GetExceptionMessage);
  end;
end;

function TrimQuotes(Value: String): String;
begin
  Result := Trim(Value);
  if (Length(Result) >= 2) and (Result[1] = '"') and
     (Result[Length(Result)] = '"') then
    Result := Copy(Result, 2, Length(Result) - 2);
end;

function ComparablePath(Value: String): String;
begin
  Result := Lowercase(RemoveBackslashUnlessRoot(TrimQuotes(Value)));
end;

function PathEntryEquals(Entry, Expected: String): Boolean;
begin
  Result := ComparablePath(Entry) = ComparablePath(Expected);
end;

function CanonicalInstallPath(Value: String): String;
var
  Unquoted: String;
begin
  Unquoted := TrimQuotes(Value);
  if Unquoted = '' then
    RaiseException('Installation path must not be empty.');
  Result := RemoveBackslashUnlessRoot(ExpandFileName(Unquoted));
  if Result = '' then
    RaiseException('Installation path could not be canonicalized: ' + Value);
end;

procedure RequireNoReparsePathComponents(Path, Description: String);
var
  CurrentPath, ParentPath: String;
begin
  CurrentPath := CanonicalInstallPath(Path);
  while CurrentPath <> '' do begin
    if PathIsReparsePoint(CurrentPath) then
      RaiseException(
        Description + ' contains a junction or symbolic link: ' + CurrentPath);
    ParentPath := ExtractFileDir(CurrentPath);
    if (ParentPath = '') or
       (CompareText(ParentPath, CurrentPath) = 0) then
      Exit;
    CurrentPath := ParentPath;
  end;
end;

function DirectoryIsEmpty(Path: String): Boolean;
var
  FindRec: TFindRec;
begin
  Result := True;
  if not DirExists(Path) then
    Exit;
  if FindFirst(AddBackslash(Path) + '*', FindRec) then begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then begin
          Result := False;
          Exit;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

function PathIsStrictChild(Path, Parent: String): Boolean;
var
  CanonicalPath, CanonicalParent: String;
begin
  CanonicalPath := Lowercase(CanonicalInstallPath(Path));
  CanonicalParent := Lowercase(CanonicalInstallPath(Parent));
  Result :=
    (CanonicalPath <> CanonicalParent) and
    (Pos(AddBackslash(CanonicalParent), AddBackslash(CanonicalPath)) = 1);
end;

function ExistingAclAnchor(Path: String): String;
var
  CurrentPath, ParentPath: String;
begin
  CurrentPath := CanonicalInstallPath(Path);
  while not DirExists(CurrentPath) and not FileExists(CurrentPath) do begin
    ParentPath := ExtractFileDir(CurrentPath);
    if (ParentPath = '') or
       (CompareText(ParentPath, CurrentPath) = 0) then
      RaiseException('No existing ACL anchor was found for: ' + Path);
    CurrentPath := ParentPath;
  end;
  Result := CurrentPath;
end;

function MachinePathAclIsTrusted(Path: String): Boolean;
var
  PowerShellPath, Command: String;
  ResultCode: Integer;
begin
  Result := False;
  PowerShellPath := ExpandConstant(
    '{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Command :=
    '$ErrorActionPreference=[System.Management.Automation.ActionPreference]::Stop;' +
    '$id=[Security.Principal.WindowsIdentity]::GetCurrent();' +
    '$s=[Collections.Generic.HashSet[string]]::new(' +
      '[StringComparer]::OrdinalIgnoreCase);' +
    'foreach($v in @(''S-1-1-0'',''S-1-5-4'',''S-1-5-11'',' +
      '''S-1-5-32-545'')){[void]$s.Add($v)};' +
    '[void]$s.Add($id.User.Value);' +
    'foreach($g in $id.Groups){if($g.Value -ne ''S-1-5-32-544'')' +
      '{[void]$s.Add($g.Value)}};' +
    '$a=Microsoft.PowerShell.Security\Get-Acl -LiteralPath ' +
      PowerShellDoubleQuotedLiteral(ExistingAclAnchor(Path)) + ';' +
    '$o=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;' +
    'if($s.Contains($o)){exit 63};' +
    '$rules=@($a.Access);if($rules.Count -eq 0){exit 64};' +
    '$danger=[uint64]0x500D0156;' +
    'foreach($r in $rules){' +
      'try{$sid=$r.IdentityReference.Translate(' +
        '[Security.Principal.SecurityIdentifier]).Value}' +
        'catch{$sid=[string]$r.IdentityReference.Value};' +
      '$rights=[uint64]([int64]$r.FileSystemRights -band 0xffffffffL);' +
      'if($r.AccessControlType -eq ' +
        '[Security.AccessControl.AccessControlType]::Allow -and ' +
        '$s.Contains($sid) -and ($rights -band $danger) -ne 0){exit 66}' +
    '};';
  if not ExecAsOriginalUser(
       PowerShellPath,
       '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' +
         Command,
       ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Exit;
  Result := ResultCode = 0;
end;

procedure RequireTrustedMachineAcl(Path, Description: String);
begin
  if not MachinePathAclIsTrusted(Path) then
    RaiseException(
      Description + ' is writable by the original user or a low-privilege ' +
      'security principal: ' + ExistingAclAnchor(Path));
end;

procedure RequireRegularPayloadDestinations(AppPath: String);
begin
  RequireRegularFile(AppPath + '\neoth.exe', 'NEOTH executable destination');
  RequireRegularFile(AppPath + '\neothd.exe', 'NEOTH compatibility destination');
  RequireRegularFile(AppPath + '\neothd-gui.exe', 'NEOTH GUI destination');
  RequireRegularFile(AppPath + '\neoth-migrate.exe', 'NEOTH migrate destination');
  RequireRegularFile(AppPath + '\neoth-relay.exe', 'NEOTH relay destination');
  RequireRegularFile(
    AppPath + '\neoth-keet-bridge.exe', 'NEOTH Keet bridge destination');
  RequireRegularFile(
    AppPath + '\freedom.yaml.example', 'NEOTH example policy destination');
  RequireRegularFile(
    AppPath + '\import-manifest.example.yaml', 'NEOTH import example destination');
  RequireRegularFile(AppPath + '\README.md', 'NEOTH README destination');
  RequireRegularFile(AppPath + '\LICENSE-MIT', 'NEOTH MIT license destination');
  RequireRegularFile(
    AppPath + '\LICENSE-APACHE', 'NEOTH Apache license destination');
  RequireRegularFile(
    AppPath + '\THIRD_PARTY_LICENSES', 'NEOTH third-party license destination');
end;

function PathContains(UserPath, Expected: String): Boolean;
var
  Remaining, Entry: String;
  Separator: Integer;
begin
  Result := False;
  Remaining := UserPath;
  while Remaining <> '' do begin
    Separator := Pos(';', Remaining);
    if Separator = 0 then begin
      Entry := Remaining;
      Remaining := '';
    end else begin
      Entry := Copy(Remaining, 1, Separator - 1);
      Delete(Remaining, 1, Separator);
    end;
    if PathEntryEquals(Entry, Expected) then begin
      Result := True;
      Exit;
    end;
  end;
end;

function EnvironmentRootKey: HKEY;
begin
  if IsAdminInstallMode then
    Result := HKLM
  else
    Result := HKCU;
end;

function EnvironmentSubkey: String;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

function QueryPathOwnership(var OwnedPath: String): Boolean;
var
  Owned: Cardinal;
begin
  OwnedPath := '';
  Result :=
    RegQueryDWordValue(
      EnvironmentRootKey, '{#InstallerStateKey}', 'PathEntryOwned', Owned) and
    (Owned = 1) and
    RegQueryStringValue(
      EnvironmentRootKey, '{#InstallerStateKey}', 'OwnedPathEntry', OwnedPath) and
    (OwnedPath <> '');
end;

procedure ClearPathOwnership;
begin
  RegDeleteValue(
    EnvironmentRootKey, '{#InstallerStateKey}', 'PathEntryOwned');
  RegDeleteValue(
    EnvironmentRootKey, '{#InstallerStateKey}', 'OwnedPathEntry');
end;

procedure RemovePathEntry(Expected: String; FailOnError: Boolean);
var
  UserPath, Remaining, Entry, Updated: String;
  Separator: Integer;
  Done, FirstOutput, Removed: Boolean;
begin
  if not RegQueryStringValue(
       EnvironmentRootKey, EnvironmentSubkey, 'Path', UserPath) then
    Exit;
  Remaining := UserPath;
  Updated := '';
  Done := False;
  FirstOutput := True;
  Removed := False;
  while not Done do begin
    Separator := Pos(';', Remaining);
    if Separator = 0 then begin
      Entry := Remaining;
      Done := True;
    end else begin
      Entry := Copy(Remaining, 1, Separator - 1);
      Delete(Remaining, 1, Separator);
    end;
    if not Removed and PathEntryEquals(Entry, Expected) then
      Removed := True
    else begin
      if not FirstOutput then
        Updated := Updated + ';';
      Updated := Updated + Entry;
      FirstOutput := False;
    end;
  end;
  if Removed then begin
    if not RegWriteExpandStringValue(
         EnvironmentRootKey, EnvironmentSubkey, 'Path', Updated) then begin
      if FailOnError then
        RaiseException('Could not remove the previous NEOTH PATH entry.')
      else
        Log('Warning: could not remove the NEOTH-owned PATH entry.');
    end;
  end;
end;

procedure AddInstallDirToPath;
var
  UserPath, InstallDir, PreviousOwnedPath: String;
  PreviouslyOwned: Boolean;
begin
  InstallDir := ExpandConstant('{app}');
  PreviouslyOwned := QueryPathOwnership(PreviousOwnedPath);
  if PreviouslyOwned and
     not PathEntryEquals(PreviousOwnedPath, InstallDir) then begin
    RemovePathEntry(PreviousOwnedPath, True);
    ClearPathOwnership;
    PreviouslyOwned := False;
  end;

  if not RegQueryStringValue(
       EnvironmentRootKey, EnvironmentSubkey, 'Path', UserPath) then
    UserPath := '';
  if PathContains(UserPath, InstallDir) then begin
    { Preserve an ownership marker from an in-place upgrade, but never claim
      a matching PATH entry that existed before the first NEOTH install. }
    if not PreviouslyOwned then
      ClearPathOwnership;
    Exit;
  end;

  { Always add a separator for a non-empty value. If PATH already ends in a
    separator, that empty entry predates NEOTH and must survive uninstall. }
  if UserPath <> '' then
    UserPath := UserPath + ';';
  UserPath := UserPath + InstallDir;
  if not RegWriteExpandStringValue(
       EnvironmentRootKey, EnvironmentSubkey, 'Path', UserPath) then
    RaiseException('Could not add NEOTH to PATH.');
  if not RegWriteDWordValue(
       EnvironmentRootKey, '{#InstallerStateKey}', 'PathEntryOwned', 1) or
     not RegWriteStringValue(
       EnvironmentRootKey, '{#InstallerStateKey}', 'OwnedPathEntry', InstallDir) then begin
    RemovePathEntry(InstallDir, False);
    ClearPathOwnership;
    RaiseException('Could not persist ownership of the NEOTH PATH entry.');
  end;
end;

function HasCommandLineParameter(Expected: String): Boolean;
var
  Index: Integer;
begin
  Result := False;
  for Index := 1 to ParamCount do begin
    if CompareText(ParamStr(Index), Expected) = 0 then begin
      Result := True;
      Exit;
    end;
  end;
end;

function CorePart(Value: String; Index: Integer): String;
var
  Core, Part: String;
  Dash, Plus, Dot, Current: Integer;
begin
  Core := Value;
  Plus := Pos('+', Core);
  if Plus > 0 then
    Core := Copy(Core, 1, Plus - 1);
  Dash := Pos('-', Core);
  if Dash > 0 then
    Core := Copy(Core, 1, Dash - 1);
  Current := 0;
  while Current <= Index do begin
    Dot := Pos('.', Core);
    if Dot = 0 then begin
      Part := Core;
      Core := '';
    end else begin
      Part := Copy(Core, 1, Dot - 1);
      Delete(Core, 1, Dot);
    end;
    if Current = Index then begin
      Result := Part;
      Exit;
    end;
    Current := Current + 1;
  end;
  Result := '0';
end;

function CompareNumericText(Left, Right: String): Integer;
begin
  while (Length(Left) > 1) and (Left[1] = '0') do
    Delete(Left, 1, 1);
  while (Length(Right) > 1) and (Right[1] = '0') do
    Delete(Right, 1, 1);
  if Length(Left) < Length(Right) then
    Result := -1
  else if Length(Left) > Length(Right) then
    Result := 1
  else if CompareStr(Left, Right) < 0 then
    Result := -1
  else if CompareStr(Left, Right) > 0 then
    Result := 1
  else
    Result := 0;
end;

function PrereleasePart(Value: String): String;
var
  Dash, Plus: Integer;
begin
  Result := '';
  Plus := Pos('+', Value);
  if Plus > 0 then
    Value := Copy(Value, 1, Plus - 1);
  Dash := Pos('-', Value);
  if Dash = 0 then
    Exit;
  Result := Copy(Value, Dash + 1, Length(Value));
end;

function TakeIdentifier(var Remaining: String): String;
var
  Dot: Integer;
begin
  Dot := Pos('.', Remaining);
  if Dot = 0 then begin
    Result := Remaining;
    Remaining := '';
  end else begin
    Result := Copy(Remaining, 1, Dot - 1);
    Delete(Remaining, 1, Dot);
  end;
end;

function IsNumericIdentifier(Value: String): Boolean;
var
  Index: Integer;
begin
  Result := Value <> '';
  for Index := 1 to Length(Value) do begin
    if (Value[Index] < '0') or (Value[Index] > '9') then begin
      Result := False;
      Exit;
    end;
  end;
end;

function IsValidPrereleaseIdentifier(Value: String): Boolean;
var
  Index: Integer;
  Character: Char;
begin
  Result := Value <> '';
  for Index := 1 to Length(Value) do begin
    Character := Value[Index];
    if not (((Character >= '0') and (Character <= '9')) or
            ((Character >= 'A') and (Character <= 'Z')) or
            ((Character >= 'a') and (Character <= 'z')) or
            (Character = '-')) then begin
      Result := False;
      Exit;
    end;
  end;
  if Result and IsNumericIdentifier(Value) and
     (Length(Value) > 1) and (Value[1] = '0') then
    Result := False;
end;

function IsValidIdentifierList(Value: String;
  RejectNumericLeadingZero: Boolean): Boolean;
var
  Identifier, Remaining: String;
begin
  Result := False;
  if (Value = '') or (Value[1] = '.') or
     (Value[Length(Value)] = '.') or (Pos('..', Value) > 0) then
    Exit;
  Remaining := Value;
  while Remaining <> '' do begin
    Identifier := TakeIdentifier(Remaining);
    if not IsValidPrereleaseIdentifier(Identifier) then begin
      { Build identifiers use the same character set, but may contain a
        numeric identifier with leading zeroes. }
      if RejectNumericLeadingZero or
         not IsNumericIdentifier(Identifier) then
        Exit;
    end;
  end;
  Result := True;
end;

function IsValidSemVer(Value: String): Boolean;
var
  Core, Prerelease, Build, Identifier: String;
  Dash, Plus, Index: Integer;
begin
  Result := False;
  if Value = '' then
    Exit;
  Plus := Pos('+', Value);
  if Plus > 0 then begin
    Build := Copy(Value, Plus + 1, Length(Value));
    Core := Copy(Value, 1, Plus - 1);
    if (Pos('+', Build) > 0) or
       not IsValidIdentifierList(Build, False) then
      Exit;
  end else begin
    Core := Value;
    Build := '';
  end;
  Dash := Pos('-', Core);
  if Dash = 0 then begin
    Prerelease := '';
  end else begin
    Prerelease := Copy(Core, Dash + 1, Length(Core));
    Core := Copy(Core, 1, Dash - 1);
    if not IsValidIdentifierList(Prerelease, True) then
      Exit;
  end;

  for Index := 0 to 2 do begin
    if Core = '' then
      Exit;
    Identifier := TakeIdentifier(Core);
    if not IsNumericIdentifier(Identifier) or
       ((Length(Identifier) > 1) and (Identifier[1] = '0')) then
      Exit;
  end;
  if Core <> '' then
    Exit;

  Result := True;
end;

function CompareSemVer(Left, Right: String): Integer;
var
  Index, Compared: Integer;
  LeftPart, RightPart, LeftPre, RightPre: String;
  LeftNumeric, RightNumeric: Boolean;
begin
  for Index := 0 to 2 do begin
    Compared := CompareNumericText(
      CorePart(Left, Index), CorePart(Right, Index));
    if Compared <> 0 then begin
      Result := Compared;
      Exit;
    end;
  end;

  LeftPre := PrereleasePart(Left);
  RightPre := PrereleasePart(Right);
  if (LeftPre = '') and (RightPre = '') then begin
    Result := 0;
    Exit;
  end;
  if LeftPre = '' then begin
    Result := 1;
    Exit;
  end;
  if RightPre = '' then begin
    Result := -1;
    Exit;
  end;

  while (LeftPre <> '') or (RightPre <> '') do begin
    if LeftPre = '' then begin
      Result := -1;
      Exit;
    end;
    if RightPre = '' then begin
      Result := 1;
      Exit;
    end;
    LeftPart := TakeIdentifier(LeftPre);
    RightPart := TakeIdentifier(RightPre);
    LeftNumeric := IsNumericIdentifier(LeftPart);
    RightNumeric := IsNumericIdentifier(RightPart);
    if LeftNumeric and RightNumeric then
      Compared := CompareNumericText(LeftPart, RightPart)
    else if LeftNumeric then
      Compared := -1
    else if RightNumeric then
      Compared := 1
    else if CompareStr(LeftPart, RightPart) < 0 then
      Compared := -1
    else if CompareStr(LeftPart, RightPart) > 0 then
      Compared := 1
    else
      Compared := 0;
    if Compared <> 0 then begin
      Result := Compared;
      Exit;
    end;
  end;
  Result := 0;
end;

procedure AssertVersionComparator;
begin
  if not IsValidSemVer('1.0.0') or
     not IsValidSemVer('1.0.0-rc.2') or
     not IsValidSemVer('1.0.0+build.01') or
     not IsValidSemVer('1.0.0-alpha+build-7.0001') or
     not IsValidSemVer('999999999999999999999999.0.0') or
     IsValidSemVer('1.0') or
     IsValidSemVer('01.0.0') or
     IsValidSemVer('1.0.0-rc.01') or
     IsValidSemVer('1.0.0+') or
     IsValidSemVer('1.0.0+build..1') or
     IsValidSemVer('1.0.0-alpha+one+two') or
     (CompareSemVer('1.0.0', '1.0.0-rc.2') <= 0) or
     (CompareSemVer('1.0.0-rc.1', '1.0.0-rc.2') >= 0) or
     (CompareSemVer('1.0.0-rc.10', '1.0.0-rc.2') <= 0) or
     (CompareSemVer('1.0.0-1', '1.0.0-alpha') >= 0) or
     (CompareSemVer('1.0.0-alpha', '1.0.0-alpha.1') >= 0) or
     (CompareSemVer('1.0.1', '1.0.0') <= 0) or
     (CompareSemVer('999999999999999999999999.0.0', '2.0.0') <= 0) or
     (CompareSemVer('1.0.0+one', '1.0.0+two') <> 0) or
     (CompareSemVer('1.0.0+build-with-dash', '1.0.0') <> 0) then
    RaiseException('Internal semantic-version comparator self-test failed.');
end;

function CommandExecutable(CommandLine: String): String;
var
  ClosingQuote, Separator: Integer;
  Remaining: String;
begin
  Remaining := Trim(CommandLine);
  if Remaining = '' then
    RaiseException('Registered uninstall command is empty.');
  if Remaining[1] = '"' then begin
    Delete(Remaining, 1, 1);
    ClosingQuote := Pos('"', Remaining);
    if ClosingQuote = 0 then
      RaiseException('Registered uninstall command has an unterminated quote.');
    Result := Copy(Remaining, 1, ClosingQuote - 1);
  end else begin
    Separator := Pos(' ', Remaining);
    if Separator = 0 then
      Result := Remaining
    else
      Result := Copy(Remaining, 1, Separator - 1);
  end;
end;

function ReadInstallRegistration(RootKey: Integer; ScopeName: String;
  var InstallLocation, DisplayVersion, UninstallCommand: String): Boolean;
var
  DisplayName, Publisher: String;
begin
  Result := RegKeyExists(RootKey, '{#UninstallKey}');
  if not Result then begin
    InstallLocation := '';
    DisplayVersion := '';
    UninstallCommand := '';
    Exit;
  end;
  if not RegQueryStringValue(
       RootKey, '{#UninstallKey}', 'InstallLocation', InstallLocation) or
     not RegQueryStringValue(
       RootKey, '{#UninstallKey}', 'DisplayVersion', DisplayVersion) or
     not RegQueryStringValue(
       RootKey, '{#UninstallKey}', 'UninstallString', UninstallCommand) or
     not RegQueryStringValue(
       RootKey, '{#UninstallKey}', 'DisplayName', DisplayName) or
     not RegQueryStringValue(
       RootKey, '{#UninstallKey}', 'Publisher', Publisher) then
    RaiseException(
      ScopeName + ' NEOTH uninstall registration is incomplete or malformed.');
  if not IsValidSemVer(DisplayVersion) or
     (CompareText(DisplayName, 'NEOTH ' + DisplayVersion) <> 0) or
     (CompareText(Publisher, 'The Geek Freaks') <> 0) then
    RaiseException(
      ScopeName + ' NEOTH uninstall registration has an invalid identity.');
end;

procedure ValidateRegisteredInstallPath(InstallLocation, UninstallCommand,
  ScopeName, ExpectedPath: String);
var
  CanonicalLocation, UninstallerPath, UninstallerName: String;
  DigitIndex: Integer;
  UninstallerNameValid: Boolean;
begin
  CanonicalLocation := CanonicalInstallPath(InstallLocation);
  if CompareText(
       RemoveBackslashUnlessRoot(TrimQuotes(InstallLocation)),
       CanonicalLocation) <> 0 then
    RaiseException(
      ScopeName + ' NEOTH InstallLocation is not canonical: ' + InstallLocation);
  if CompareText(CanonicalLocation, ExpectedPath) <> 0 then
    RaiseException(
      ScopeName + ' NEOTH registration owns ' + CanonicalLocation +
      ', not the requested target ' + ExpectedPath + '.');
  RequireNoReparsePathComponents(
    CanonicalLocation, ScopeName + ' NEOTH InstallLocation');
  RequireRegularDirectory(
    CanonicalLocation, ScopeName + ' NEOTH InstallLocation');
  if not DirExists(CanonicalLocation) then
    RaiseException(
      ScopeName + ' NEOTH InstallLocation does not exist: ' + CanonicalLocation);

  UninstallerPath := CanonicalInstallPath(
    CommandExecutable(UninstallCommand));
  UninstallerName := Lowercase(ExtractFileName(UninstallerPath));
  UninstallerNameValid := Length(UninstallerName) = 12;
  if UninstallerNameValid then begin
    if (Copy(UninstallerName, 1, 5) <> 'unins') or
       (Copy(UninstallerName, 9, 4) <> '.exe') then
      UninstallerNameValid := False;
    for DigitIndex := 6 to 8 do begin
      if (UninstallerName[DigitIndex] < '0') or
         (UninstallerName[DigitIndex] > '9') then
        UninstallerNameValid := False;
    end;
  end;
  if (CompareText(ExtractFileDir(UninstallerPath), CanonicalLocation) <> 0) or
     not UninstallerNameValid or
     (CompareText(Trim(UninstallCommand), AddQuotes(UninstallerPath)) <> 0) then
    RaiseException(
      ScopeName + ' NEOTH uninstall command is not the canonical Inno ' +
      'uninstaller inside its InstallLocation.');
  RequireNoReparsePathComponents(
    UninstallerPath, ScopeName + ' NEOTH uninstaller');
  RequireRegularFile(UninstallerPath, ScopeName + ' NEOTH uninstaller');
  if not FileExists(UninstallerPath) then
    RaiseException(
      ScopeName + ' NEOTH uninstaller does not exist: ' + UninstallerPath);
end;

procedure AssertInstallTargetOwnership;
var
  AppPath, ProgramFilesPath: String;
  UserLocation, UserVersion, UserUninstall: String;
  MachineLocation, MachineVersion, MachineUninstall: String;
  UserRegistered, MachineRegistered: Boolean;
begin
  AppPath := CanonicalInstallPath(ExpandConstant('{app}'));
  if CompareText(
       RemoveBackslashUnlessRoot(ExpandConstant('{app}')), AppPath) <> 0 then
    RaiseException('Requested NEOTH install target is not canonical: ' +
      ExpandConstant('{app}'));
  if FileExists(AppPath) then
    RaiseException('NEOTH install target is a file, not a directory: ' + AppPath);
  RequireNoReparsePathComponents(AppPath, 'NEOTH install target');
  RequireRegularDirectory(AppPath, 'NEOTH install target');
  RequireRegularPayloadDestinations(AppPath);

  UserRegistered := ReadInstallRegistration(
    HKCU, 'Per-user', UserLocation, UserVersion, UserUninstall);
  MachineRegistered := ReadInstallRegistration(
    HKLM, 'All-users', MachineLocation, MachineVersion, MachineUninstall);
  if UserRegistered and MachineRegistered then
    RaiseException(
      'NEOTH has ambiguous per-user and all-users uninstall registrations.');
  if IsAdminInstallMode then begin
    if UserRegistered then
      RaiseException(
        'A per-user NEOTH registration cannot authorize an all-users install.');
    ProgramFilesPath := CanonicalInstallPath(ExpandConstant('{autopf}'));
    if not PathIsStrictChild(AppPath, ProgramFilesPath) then
      RaiseException(
        'All-users NEOTH must use a new or registered path below Program Files; ' +
        'user-writable custom targets are not trusted.');
    RequireTrustedMachineAcl(AppPath, 'All-users NEOTH install target');
    if MachineRegistered then begin
      ValidateRegisteredInstallPath(
        MachineLocation, MachineUninstall, 'All-users', AppPath);
      if not FileExists(AppPath + '\neoth.exe') then
        RaiseException(
          'All-users NEOTH recovery executable does not exist: ' +
          AppPath + '\neoth.exe');
      RequireTrustedMachineAcl(
        AppPath + '\neoth.exe', 'All-users NEOTH recovery executable');
    end else if DirExists(AppPath) then
      RaiseException(
        'A fresh all-users NEOTH target must not already exist: ' + AppPath);
  end else begin
    if MachineRegistered then
      RaiseException(
        'An all-users NEOTH registration cannot authorize a per-user install.');
    if UserRegistered then begin
      ValidateRegisteredInstallPath(
        UserLocation, UserUninstall, 'Per-user', AppPath);
    end else if DirExists(AppPath) and not DirectoryIsEmpty(AppPath) then
      RaiseException(
        'The requested NEOTH target is non-empty and has no matching ' +
        'per-user uninstall registration: ' + AppPath);
  end;
end;

procedure RecoverSelfKnowledgeTransaction;
var
  LivePath, StagePath, BackupPath, MarkerPath, MarkerTempPath: String;
  MarkerBytes: AnsiString;
  MarkerVersion: String;
  LiveVerified, BackupVerified: Boolean;
begin
  LivePath := SelfKnowledgeLivePath;
  StagePath := SelfKnowledgeStagePath;
  BackupPath := SelfKnowledgeBackupPath;
  MarkerPath := SelfKnowledgeCommitMarkerPath;
  MarkerTempPath := MarkerPath + '.tmp';

  RequireRegularTree(LivePath, 'NEOTH self-knowledge snapshot');
  RequireRegularTree(StagePath, 'NEOTH self-knowledge transaction stage');
  RequireRegularTree(BackupPath, 'NEOTH self-knowledge transaction backup');
  RequireRegularFile(MarkerPath, 'NEOTH self-knowledge commit marker');
  RequireRegularFile(MarkerTempPath, 'NEOTH self-knowledge temporary commit marker');

  { Marker versions describe the installer that created the state, not the
    installer recovering it. N is therefore valid during an N+1 cleanup. }
  if FileExists(MarkerPath) then begin
    if not LoadStringFromFile(MarkerPath, MarkerBytes) then
      RaiseException('Could not read the NEOTH self-knowledge commit marker.');
    MarkerVersion := MarkerBytes;
    if not IsValidSemVer(MarkerVersion) then
      RaiseException('NEOTH self-knowledge commit marker is malformed.');
  end;
  if FileExists(MarkerTempPath) then begin
    if not LoadStringFromFile(MarkerTempPath, MarkerBytes) then
      RaiseException('Could not read the NEOTH self-knowledge transaction marker.');
    MarkerVersion := MarkerBytes;
    if not IsValidSemVer(MarkerVersion) then
      RaiseException('NEOTH self-knowledge transaction marker is malformed.');
  end;

  { Markers are recovery hints, never authority: a local actor can forge them.
    Before any installed executable may run, the exact registered path/scope,
    a non-elevated original-user token, and matching valid Authenticode signer
    are required. The signed executable then performs the closed-set check. }
  if DirExists(BackupPath) then begin
    LiveVerified := DirExists(LivePath) and
      VerifyInstalledSelfKnowledgeSnapshot(LivePath);
    BackupVerified := VerifyInstalledSelfKnowledgeSnapshot(BackupPath);
    if LiveVerified then begin
      DeleteOwnedDirectory(BackupPath, 'superseded NEOTH self-knowledge backup');
    end else if BackupVerified then begin
      DeleteOwnedDirectory(LivePath, 'uncommitted NEOTH self-knowledge snapshot');
      if not RenameFile(BackupPath, LivePath) then
        RaiseException('Could not restore the verified previous NEOTH self-knowledge snapshot.');
    end else begin
      RaiseException(
        'Neither live nor backup self-knowledge matches the installed NEOTH executable.');
    end;
  end else if FileExists(MarkerPath) then begin
    if not DirExists(LivePath) or
       not VerifyInstalledSelfKnowledgeSnapshot(LivePath) then
      RaiseException(
        'Committed NEOTH self-knowledge state does not match the installed executable.');
  end else if FileExists(MarkerTempPath) and DirExists(LivePath) then begin
    if not VerifyInstalledSelfKnowledgeSnapshot(LivePath) then
      RaiseException(
        'Interrupted NEOTH self-knowledge state does not match the installed executable.');
  end else if FileExists(MarkerTempPath) then begin
    { A first-install interruption before the stage rename has neither live N
      nor a backup. Discard the incomplete stage so this installer can repair
      it; a forged marker can never delete an existing live snapshot. }
    Log('Discarding an incomplete fresh-install self-knowledge transaction.');
  end;

  DeleteOwnedDirectory(StagePath, 'stale NEOTH self-knowledge transaction stage');
  DeleteOwnedFile(MarkerPath, 'NEOTH self-knowledge commit marker');
  DeleteOwnedFile(MarkerTempPath, 'stale NEOTH self-knowledge transaction marker');
end;

function InitializeSetup(): Boolean;
var
  UserVersion, MachineVersion, InstalledVersion: String;
  UserInstalled, MachineInstalled: Boolean;
begin
  Result := True;
  AssertVersionComparator;
  if not IsValidSemVer('{#AppVersion}') then begin
    MsgBox('This installer contains an invalid semantic version.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  UserVersion := '';
  MachineVersion := '';
  UserInstalled := RegKeyExists(HKCU, '{#UninstallKey}');
  MachineInstalled := RegKeyExists(HKLM, '{#UninstallKey}');
  if (UserInstalled and
      (not RegQueryStringValue(
        HKCU, '{#UninstallKey}', 'DisplayVersion', UserVersion) or
       not IsValidSemVer(UserVersion))) or
     (MachineInstalled and
      (not RegQueryStringValue(
        HKLM, '{#UninstallKey}', 'DisplayVersion', MachineVersion) or
       not IsValidSemVer(MachineVersion))) then begin
    MsgBox(
      'Existing NEOTH version metadata is missing or malformed.' + #13#10 +
      'Per-user: ' + UserVersion + #13#10 +
      'All-users: ' + MachineVersion + #13#10 +
      'Uninstall or repair the existing installation before continuing. ' +
      '/ALLOWDOWNGRADE never bypasses corrupt installation metadata.',
      mbError, MB_OK);
    Result := False;
    Exit;
  end;
  if UserInstalled and MachineInstalled then begin
    MsgBox(
      'NEOTH is installed in both per-user and all-users scope. ' +
      'Uninstall one copy before continuing so PATH resolution is deterministic.',
      mbError, MB_OK);
    Result := False;
    Exit;
  end;
  if UserInstalled then
    InstalledVersion := UserVersion
  else
    InstalledVersion := '';
  if MachineInstalled and
     ((InstalledVersion = '') or
      (CompareSemVer(MachineVersion, InstalledVersion) > 0)) then
    InstalledVersion := MachineVersion;
  if (InstalledVersion <> '') and
     (CompareSemVer(InstalledVersion, '{#AppVersion}') > 0) and
     not HasCommandLineParameter('/ALLOWDOWNGRADE') then begin
    MsgBox(
      'A newer NEOTH version (' + InstalledVersion + ') is already installed.' + #13#10 +
      'Use the newer installer, or pass /ALLOWDOWNGRADE for an explicit recovery downgrade.',
      mbError, MB_OK);
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  UserInstalled, MachineInstalled: Boolean;
begin
  Result := '';
  UserInstalled := RegKeyExists(HKCU, '{#UninstallKey}');
  MachineInstalled := RegKeyExists(HKLM, '{#UninstallKey}');
  if UserInstalled and MachineInstalled then begin
    Result :=
      'NEOTH is already installed in both per-user and all-users scope. ' +
      'Uninstall one copy before continuing so PATH resolution is deterministic.';
    Exit;
  end;
  if IsAdminInstallMode and UserInstalled then begin
    Result :=
      'A per-user NEOTH installation already exists. Uninstall it before ' +
      'installing for all users.';
    Exit;
  end;
  if not IsAdminInstallMode and MachineInstalled then begin
    Result :=
      'An all-users NEOTH installation already exists. Rerun this installer ' +
      'as administrator with /ALLUSERS, or uninstall the all-users copy first.';
    Exit;
  end;
  try
    AssertInstallTargetOwnership;
  except
    Result :=
      'NEOTH refused the requested installation target before writing files: ' +
      GetExceptionMessage;
    Exit;
  end;
  try
    RecoverSelfKnowledgeTransaction;
  except
    Result :=
      'NEOTH could not safely recover its self-knowledge install transaction: ' +
      GetExceptionMessage;
  end;
end;

function InitializeUninstall(): Boolean;
begin
  UninstallOwnsPathEntry := QueryPathOwnership(UninstallOwnedPath);
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    CommitSelfKnowledgeTransaction;
    AddInstallDirToPath;
  end;
end;

procedure DeinitializeSetup;
begin
  if SelfKnowledgeSwapActive and not SelfKnowledgeCommitted then begin
    try
      RollbackSelfKnowledgeTransaction;
    except
      Log('Error: NEOTH self-knowledge rollback failed during setup shutdown: ' +
        GetExceptionMessage);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then begin
    if UninstallOwnsPathEntry then
      RemovePathEntry(UninstallOwnedPath, False);
    ClearPathOwnership;
  end;
end;
