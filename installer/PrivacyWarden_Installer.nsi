; PrivacyWarden Installer — Single Unified Executable
; Built with NSIS (Nullsoft Scriptable Install System)
; Author: Aya Yoki (AyaYokiVT) -- Gearlight Labs

;--------------------------------
; General

!define PRODUCT_NAME      "PrivacyWarden"
!define PRODUCT_VERSION   "1.3.1"
!define PRODUCT_PUBLISHER "Aya Yoki (AyaYokiVT) - Gearlight Labs"
!define PRODUCT_AUTHOR    "Aya Yoki (AyaYokiVT)"
!define PRODUCT_CONTACT   "gearlightlabs@gmail.com"
!define PRODUCT_URL       "https://github.com/Gearlight-Labs/PrivacyWarden"
!define PRODUCT_EXE       "PrivacyWarden.exe"
!define SERVICE_NAME      "PrivacyWarden"
!define INSTALL_DIR       "$PROGRAMFILES64\PrivacyWarden"

; RELEASE_DIR is the folder containing all built assets.
!define RELEASE_DIR "..\PrivacyWarden_Release"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "PrivacyWarden-Setup-v${PRODUCT_VERSION}.exe"
InstallDir "${INSTALL_DIR}"
InstallDirRegKey HKLM "Software\GearLightLabs\PrivacyWarden" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

Unicode True

;--------------------------------
; Variables

Var IS_UPGRADE

;--------------------------------
; Interface

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "Sections.nsh"

!define MUI_ICON   "${RELEASE_DIR}\tray_icon.ico"
!define MUI_UNICON "${RELEASE_DIR}\tray_icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT

; Welcome/Finish page title color
!define MUI_WELCOMEPAGE_TITLE_COLOR "C0002A"
!define MUI_FINISHPAGE_TITLE_COLOR  "C0002A"

; Welcome page
!define MUI_WELCOMEPAGE_TITLE "Welcome to PrivacyWarden Setup"
!define MUI_WELCOMEPAGE_TEXT "PrivacyWarden runs 24/7 in the background and automatically switches Mullvad VPN between Privacy Mode (VPN on) and Streaming Mode (VPN off, DNS locked) so you never have to think about it.$\r$\n$\r$\nZero telemetry. No data collection. 100% local.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME

; License page
!insertmacro MUI_PAGE_LICENSE "${RELEASE_DIR}\LICENSE"

; Components page (shows optional sections)
!insertmacro MUI_PAGE_COMPONENTS

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Install files page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!define MUI_FINISHPAGE_TITLE "You're all set!"
!define MUI_FINISHPAGE_TEXT "PrivacyWarden is installed and running in the background. You don't have to do anything else.$\r$\n$\r$\nJust make sure Mullvad VPN is installed and it'll handle everything automatically.$\r$\n$\r$\nZero telemetry, no data collection, 100% local.$\r$\n$\r$\nStay safe out there.$\r$\n- Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com"
!define MUI_FINISHPAGE_LINK "Visit GitHub Repository"
!define MUI_FINISHPAGE_LINK_LOCATION "${PRODUCT_URL}"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Version Info (shown in Windows file properties)

VIProductVersion "1.3.1.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName"     "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion"  "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName"     "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright"  "2026 Aya Yoki (AyaYokiVT) - Gearlight Labs"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${PRODUCT_NAME} Installer"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion"     "1.3.1.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "Comments"        "Created by Aya Yoki (AyaYokiVT) - gearlightlabs@gmail.com"

;--------------------------------
; Installer Init — Detect upgrade vs fresh install

Function .onInit
  ; Check if PrivacyWarden is already installed by reading the registry
  ReadRegStr $0 HKLM "Software\GearLightLabs\PrivacyWarden" "Version"
  ${If} $0 != ""
    StrCpy $IS_UPGRADE "1"
    MessageBox MB_OKCANCEL|MB_ICONINFORMATION "PrivacyWarden v$0 is already installed.$\r$\n$\r$\nThis will upgrade it to v${PRODUCT_VERSION}.$\r$\nYour settings and logs will be preserved.$\r$\n$\r$\nClick OK to continue or Cancel to abort." IDOK +2
    Abort
  ${Else}
    StrCpy $IS_UPGRADE "0"
  ${EndIf}
FunctionEnd

;--------------------------------
; Sections

Section "PrivacyWarden (required)" SecMain
  SectionIn RO

  ; Kill the tray app if running (handles both old PrivacyWardenTray.exe and new unified exe --tray)
  nsExec::ExecToLog 'taskkill /IM PrivacyWardenTray.exe /F'
  nsExec::ExecToLog 'taskkill /IM PrivacyWarden.exe /F'
  Sleep 1000

  ; Stop existing service if running
  nsExec::ExecToLog 'sc stop "${SERVICE_NAME}"'
  Sleep 2000

  ; Delete old service registration (will be re-created with correct path)
  nsExec::ExecToLog 'sc delete "${SERVICE_NAME}"'
  Sleep 1000

  ; Install core files — ONE executable, ONE icon, ONE license
  SetOutPath "$INSTDIR"
  File "${RELEASE_DIR}\${PRODUCT_EXE}"
  File "${RELEASE_DIR}\tray_icon.ico"
  File "${RELEASE_DIR}\LICENSE"
  File "${RELEASE_DIR}\CHANGELOG.md"

  ; Clean up old separate tray exe if upgrading from older version
  ${If} $IS_UPGRADE == "1"
    Delete "$INSTDIR\PrivacyWardenTray.exe"
  ${EndIf}

  ; Register Windows Service
  ; SECURITY: binPath value is double-quoted to prevent unquoted service path privilege escalation
  nsExec::ExecToLog 'sc create "${SERVICE_NAME}" binPath= "\"$INSTDIR\${PRODUCT_EXE}\"" DisplayName= "${PRODUCT_NAME}" start= auto'
  nsExec::ExecToLog 'sc description "${SERVICE_NAME}" "Automates Mullvad VPN toggling, DNS leak protection, and security monitoring for VTubers. Created by Aya Yoki (AyaYokiVT)."'
  nsExec::ExecToLog 'sc start "${SERVICE_NAME}"'

  ; Create desktop shortcut (launches tray mode)
  CreateShortcut "$DESKTOP\PrivacyWarden.lnk" "$INSTDIR\${PRODUCT_EXE}" "--tray" "$INSTDIR\tray_icon.ico" 0

  ; Create Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\PrivacyWarden"
  CreateShortcut "$SMPROGRAMS\PrivacyWarden\PrivacyWarden.lnk" "$INSTDIR\${PRODUCT_EXE}" "--tray" "$INSTDIR\tray_icon.ico" 0
  CreateShortcut "$SMPROGRAMS\PrivacyWarden\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

  ; Register tray app to auto-start on user login (same exe, --tray flag)
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PrivacyWardenTray" '"$INSTDIR\${PRODUCT_EXE}" --tray'

  ; Remove old tray auto-start entry if it pointed to the separate exe
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PrivacyWardenTray_old"

  ; Launch tray app immediately after install
  Exec '"$INSTDIR\${PRODUCT_EXE}" --tray'

  ; Write registry keys
  WriteRegStr HKLM "Software\GearLightLabs\PrivacyWarden" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\GearLightLabs\PrivacyWarden" "Version"    "${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden" "DisplayName"     "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden" "DisplayIcon"     "$INSTDIR\tray_icon.ico"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden" "Publisher"       "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden" "URLInfoAbout"    "${PRODUCT_URL}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden" "DisplayVersion"  "${PRODUCT_VERSION}"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden" "NoRepair"  1

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

SectionEnd

Section "Documentation" SecDocs
  SetOutPath "$INSTDIR\docs"
  File "${RELEASE_DIR}\USER_GUIDE.md"
  File "${RELEASE_DIR}\FAQ.md"
  File "${RELEASE_DIR}\SECURITY.md"
SectionEnd

; Optional: Full Security Hardening (Network + Anti-Harassment)
; Unchecked by default -- user must opt in
Section /o "Security Hardening (recommended)" SecHarden

  ; Copy the combined hardening script to the install directory
  SetOutPath "$INSTDIR"
  File "${RELEASE_DIR}\Setup-PrivacyWarden-Hardening.ps1"

  ; Run the hardening script silently via PowerShell
  nsExec::ExecToLog 'powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\Setup-PrivacyWarden-Hardening.ps1"'

SectionEnd

;--------------------------------
; Section descriptions (shown when hovering over each option)

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain}   "The PrivacyWarden unified service and system tray app — one single program that handles everything. Automatically manages Mullvad VPN and DNS protection while you stream. Required."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDocs}   "Documentation files: User Guide, FAQ, and Security Policy."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecHarden} "Applies 25 security hardening steps in one pass: disables LLMNR, NetBIOS, WPAD, Windows telemetry, Recall AI, and protects against Discord token grabbers, IP loggers, RATs, and credential dumpers. Recommended for all users. Can be re-run manually at any time."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
; Uninstaller helper: un.StrContains

Function un.StrContains
  Exch $R1  ; needle
  Exch
  Exch $R0  ; haystack
  Push $R2
  Push $R3
  Push $R4
  StrLen $R3 $R1
  StrCpy $R4 0
  loop:
    StrCpy $R2 $R0 $R3 $R4
    StrCmp $R2 "" done_notfound
    StrCmp $R2 $R1 done_found
    IntOp $R4 $R4 + 1
    Goto loop
  done_found:
    StrCpy $R0 $R1
    Goto done
  done_notfound:
    StrCpy $R0 ""
  done:
  Pop $R4
  Pop $R3
  Pop $R2
  Exch $R0
  Exch
  Pop $R1
FunctionEnd

;--------------------------------
; Uninstaller

Section "Uninstall"

  ; Kill the tray app
  nsExec::ExecToLog 'taskkill /IM PrivacyWarden.exe /F'
  Sleep 1000

  ; Stop the service and wait until fully stopped
  nsExec::ExecToLog 'sc stop "${SERVICE_NAME}"'

  StrCpy $0 0
  ${Do}
    Sleep 2000
    nsExec::ExecToStack 'sc query "${SERVICE_NAME}"'
    Pop $1
    Pop $2
    ${If} $1 != 0
      StrCpy $0 15
    ${EndIf}
    ${If} $2 != ""
      Push $2
      Push "RUNNING"
      Call un.StrContains
      Pop $3
      ${If} $3 == ""
        StrCpy $0 15
      ${EndIf}
    ${EndIf}
    IntOp $0 $0 + 1
  ${LoopUntil} $0 >= 15

  Sleep 1000

  ; Delete the Windows Service
  nsExec::ExecToLog 'sc delete "${SERVICE_NAME}"'
  Sleep 1000

  ; SECURITY: Strip deny ACEs from ProgramData folder before deletion.
  nsExec::ExecToLog 'icacls "$APPDATA\..\..\ProgramData\PrivacyWarden" /remove:d *S-1-1-0 /t /c'
  nsExec::ExecToLog 'icacls "$APPDATA\..\..\ProgramData\PrivacyWarden" /remove:d *S-1-5-11 /t /c'
  nsExec::ExecToLog 'icacls "$APPDATA\..\..\ProgramData\PrivacyWarden" /remove:d *S-1-5-32-545 /t /c'
  nsExec::ExecToLog 'icacls "$APPDATA\..\..\ProgramData\PrivacyWarden" /grant *S-1-5-32-544:F /t /c'
  
  ; Delete specific files instead of the whole directory to preserve Logs
  Delete "$APPDATA\..\..\ProgramData\PrivacyWarden\config.json"
  Delete "$APPDATA\..\..\ProgramData\PrivacyWarden\status.json"
  Delete "$APPDATA\..\..\ProgramData\PrivacyWarden\status.json.sig"
  Delete "$APPDATA\..\..\ProgramData\PrivacyWarden\hmac_seed.bin"

  ; Delete installed files — only ONE exe now
  Delete "$INSTDIR\Setup-PrivacyWarden-Hardening.ps1"
  Delete /REBOOTOK "$INSTDIR\${PRODUCT_EXE}"
  Delete "$INSTDIR\tray_icon.ico"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\CHANGELOG.md"
  Delete "$INSTDIR\docs\USER_GUIDE.md"
  Delete "$INSTDIR\docs\FAQ.md"
  Delete "$INSTDIR\docs\SECURITY.md"
  Delete "$INSTDIR\Uninstall.exe"

  ; Clean up legacy files from older versions
  Delete "$INSTDIR\PrivacyWardenTray.exe"
  Delete "$INSTDIR\FAQ.md"
  Delete "$INSTDIR\USER_GUIDE.md"
  Delete "$INSTDIR\SECURITY.md"

  ; Remove directories
  RMDir "$INSTDIR\docs"
  RMDir /r "$INSTDIR"

  ; Remove tray auto-start registry entry
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PrivacyWardenTray"

  ; Remove shortcuts
  Delete "$DESKTOP\PrivacyWarden.lnk"
  Delete "$SMPROGRAMS\PrivacyWarden\PrivacyWarden.lnk"
  Delete "$SMPROGRAMS\PrivacyWarden\Uninstall.lnk"
  RMDir  "$SMPROGRAMS\PrivacyWarden"

  ; Remove registry keys
  DeleteRegKey HKLM "Software\GearLightLabs\PrivacyWarden"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden"

  MessageBox MB_ICONINFORMATION|MB_OK "PrivacyWarden has been uninstalled.$\r$\n$\r$\nEverything has been cleaned up.$\r$\n$\r$\nNote: your audit logs at C:\ProgramData\PrivacyWarden\Logs\ were kept on purpose. Those are your records.$\r$\n$\r$\nThanks for using it. Stay safe.$\r$\n- Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com"

SectionEnd
