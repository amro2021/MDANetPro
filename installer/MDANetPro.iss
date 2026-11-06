; Inno Setup script for MDANetPro (https://jrsoftware.org/isinfo.php)
;
; Build steps (on Windows):
;   1. pyinstaller MDANetClient.spec          -> dist\MDANetClient.exe
;   2. Open this file in Inno Setup and click Compile (or: iscc installer\MDANetPro.iss)
;   -> installer\Output\MDANetPro-Setup.exe
;
; The installer runs as administrator once, so it also adds the Windows Firewall rules.
; Users then never see the "Allow network access" step. App data goes to
; %LOCALAPPDATA%\MDANetPro (see app_data_dir() in mdaclient.py).

#define AppName "MDANetPro"
#define AppVersion "0.2"
#define AppExe "MDANetClient.exe"
#define NodePort "50404"
#define DiscoveryPort "50405"

[Setup]
AppId={{00EC8C59-99DE-41D7-8EC5-51438A1EDE7F}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=MDANetPro
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
PrivilegesRequired=admin
OutputDir=Output
OutputBaseFilename=MDANetPro-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExe}

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Run]
; Remove old rules first so reinstalling does not pile up duplicates.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MDANetPro node (TCP {#NodePort})"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MDANetPro discovery (UDP {#DiscoveryPort})"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MDANetPro ping"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""MDANetPro node (TCP {#NodePort})"" dir=in action=allow protocol=TCP localport={#NodePort} profile=any"; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""MDANetPro discovery (UDP {#DiscoveryPort})"" dir=in action=allow protocol=UDP localport={#DiscoveryPort} profile=any"; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""MDANetPro ping"" dir=in action=allow protocol=icmpv4:8,any profile=any"; Flags: runhidden
Filename: "{app}\{#AppExe}"; Description: "Start {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MDANetPro node (TCP {#NodePort})"""; Flags: runhidden; RunOnceId: "fwtcp"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MDANetPro discovery (UDP {#DiscoveryPort})"""; Flags: runhidden; RunOnceId: "fwudp"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MDANetPro ping"""; Flags: runhidden; RunOnceId: "fwping"
