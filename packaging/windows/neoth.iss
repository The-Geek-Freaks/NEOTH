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
  end;
end;

function InitializeUninstall(): Boolean;
begin
  UninstallOwnsPathEntry := QueryPathOwnership(UninstallOwnedPath);
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    AddInstallDirToPath;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then begin
    if UninstallOwnsPathEntry then
      RemovePathEntry(UninstallOwnedPath, False);
    ClearPathOwnership;
  end;
end;
