; Inno Setup script for the Windows installer (https://jrsoftware.org/isinfo.php).
; Built by the GitHub Actions workflow:
;   iscc /DAppVersion=1.5.5 /DSourceDir="dist\Password Manager" /DOutputDir=dist packaging\windows\installer.iss
;
; Installs for the current user only (no administrator rights), into
; %LOCALAPPDATA%\Programs\Password Manager, with a Start menu shortcut and an
; optional desktop shortcut. It also registers securevault_host.exe as the
; native messaging host of the Firefox extension (browser-extension/).
; Uninstalling removes the program and that registration only: the vault,
; settings and log in %APPDATA%\SecureVault are kept.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\Password Manager"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
; Fixed id: newer versions install over older ones
AppId={{6F3B2A51-4C7E-4E2B-9A61-5D0C8E7B4F12}
AppName=Password Manager
AppVersion={#AppVersion}
AppVerName=Password Manager {#AppVersion}
AppPublisher=SecureVault
AppPublisherURL=https://github.com/sashablacky/PasswordManager
AppSupportURL=https://github.com/sashablacky/PasswordManager/releases/latest
DefaultDirName={localappdata}\Programs\Password Manager
DefaultGroupName=Password Manager
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=PasswordManager-{#AppVersion}-Windows-Setup
SetupIconFile=SecureVault.ico
UninstallDisplayIcon={app}\Password Manager.exe
UninstallDisplayName=Password Manager
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; The program must be closed to be updated or removed
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Password Manager"; Filename: "{app}\Password Manager.exe"
Name: "{autodesktop}\Password Manager"; Filename: "{app}\Password Manager.exe"; Tasks: desktopicon

; The Firefox extension finds the program through this key (HKCU, or HKLM when
; installed for all users) and the manifest written by CurStepChanged below
[Registry]
Root: HKA; Subkey: "Software\Mozilla\NativeMessagingHosts\com.securevault.bridge"; ValueType: string; ValueName: ""; ValueData: "{app}\com.securevault.bridge.json"; Flags: uninsdeletekey

[Run]
Filename: "{app}\Password Manager.exe"; Description: "{cm:LaunchProgram,Password Manager}"; Flags: nowait postinstall skipifsilent

; Only what the installer wrote itself: the user's data in %APPDATA%\SecureVault stays
[UninstallDelete]
Type: files; Name: "{app}\com.securevault.bridge.json"

[Code]
// JSON string of ASCII characters only: anything else (a Cyrillic user name
// in the path) as \uXXXX, so the file's encoding does not matter
function JsonString(S: String): String;
var
  I: Integer;
  C: Char;
begin
  Result := '"';
  for I := 1 to Length(S) do
  begin
    C := S[I];
    if (C = '\') or (C = '"') then
      Result := Result + '\' + C
    else if (Ord(C) < 32) or (Ord(C) > 126) then
      Result := Result + Format('\u%.4x', [Ord(C)])
    else
      Result := Result + C;
  end;
  Result := Result + '"';
end;

// The host manifest, the same as browser-extension/install_firefox.py writes
procedure CurStepChanged(CurStep: TSetupStep);
var
  Manifest: String;
begin
  if CurStep = ssPostInstall then
  begin
    Manifest := '{' + #13#10 +
      '  "name": "com.securevault.bridge",' + #13#10 +
      '  "description": "SecureVault password manager",' + #13#10 +
      '  "path": ' + JsonString(ExpandConstant('{app}\securevault_host.exe')) + ',' + #13#10 +
      '  "type": "stdio",' + #13#10 +
      '  "allowed_extensions": ["securevault-bridge@sashablacky"]' + #13#10 +
      '}' + #13#10;
    if not SaveStringToFile(ExpandConstant('{app}\com.securevault.bridge.json'), Manifest, False) then
      Log('Could not write the Firefox native messaging manifest');
  end;
end;
