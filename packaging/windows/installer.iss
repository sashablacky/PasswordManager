; Inno Setup script for the Windows installer (https://jrsoftware.org/isinfo.php).
; Built by the GitHub Actions workflow:
;   iscc /DAppVersion=1.5.5 /DSourceDir="dist\Password Manager" /DOutputDir=dist packaging\windows\installer.iss
;
; Installs for the current user only (no administrator rights), into
; %LOCALAPPDATA%\Programs\Password Manager, with a Start menu shortcut and an
; optional desktop shortcut. Uninstalling removes the program only: the vault,
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

[Run]
Filename: "{app}\Password Manager.exe"; Description: "{cm:LaunchProgram,Password Manager}"; Flags: nowait postinstall skipifsilent

; Nothing in [UninstallDelete]: the user's data in %APPDATA%\SecureVault stays
