; StreamGuard - Setup Wizard
; Built with NSIS (Nullsoft Scriptable Install System)

;--------------------------------
; General

!define PRODUCT_NAME "StreamGuard"
!define PRODUCT_VERSION "1.1.1"
!define PRODUCT_PUBLISHER "Aya Yoki (AyaYokiVT) - Gearlight Labs"
!define PRODUCT_AUTHOR "Aya Yoki (AyaYokiVT)"
!define PRODUCT_CONTACT "gearlightlabs@gmail.com"
!define PRODUCT_URL "https://github.com/Gearlight-Labs/StreamGuard"
!define PRODUCT_EXE "StreamGuard.exe"
!define SERVICE_NAME "StreamGuard"
!define INSTALL_DIR "$PROGRAMFILES64\StreamGuard"

; RELEASE_DIR is the folder containing all built assets.
; The CI workflow creates it at the repo root, so we reference it
; relative to the repo root using /NOCD in the makensis call.
!define RELEASE_DIR "..\StreamGuard_Release"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "StreamGuard-Setup-v1.1.1.exe"
InstallDir "${INSTALL_DIR}"
InstallDirRegKey HKLM "Software\GearLightLabs\StreamGuard" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
Unicode True

;--------------------------------
; Interface

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ICON "${RELEASE_DIR}\tray_icon.ico"
!define MUI_UNICON "${RELEASE_DIR}\tray_icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT

; Welcome/Finish page sidebar color
!define MUI_WELCOMEPAGE_TITLE_COLOR "C0002A"
!define MUI_FINISHPAGE_TITLE_COLOR "C0002A"

; Welcome page
!define MUI_WELCOMEPAGE_TITLE "Welcome to StreamGuard Setup"
!define MUI_WELCOMEPAGE_TEXT "StreamGuard runs 24/7 in the background and automatically switches Mullvad VPN between Privacy Mode (VPN on) and Streaming Mode (VPN off, DNS locked) so you never have to think about it.$\r$\n$\r$\nZero telemetry. No data collection. 100% local.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME

; License page
!insertmacro MUI_PAGE_LICENSE "${RELEASE_DIR}\LICENSE"

; Components page
!insertmacro MUI_PAGE_COMPONENTS

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Install files page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!define MUI_FINISHPAGE_TITLE "You're all set!"
!define MUI_FINISHPAGE_TEXT "StreamGuard is installed and running in the background. You don't have to do anything else.$\r$\n$\r$\nJust make sure Mullvad VPN is installed and it'll handle everything automatically.$\r$\n$\r$\nZero telemetry, no data collection, 100% local.$\r$\n$\r$\nStay safe out there.$\r$\n- Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com"
!define MUI_FINISHPAGE_LINK "Visit GitHub Repository"
!define MUI_FINISHPAGE_LINK_LOCATION "${PRODUCT_URL}"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Languages
!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Version Info

VIProductVersion "1.1.1.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "2026 Aya Yoki (AyaYokiVT) - Gearlight Labs"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${PRODUCT_NAME} Installer"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "1.1.1.0"
VIAddVersionKey /LANG=${LANG_ENGLISH} "Comments" "Created by Aya Yoki (AyaYokiVT) - gearlightlabs@gmail.com"

;--------------------------------
; Sections

Section "StreamGuard (required)" SecMain
  SectionIn RO

  ; Stop existing service if running
  nsExec::ExecToLog 'sc stop "${SERVICE_NAME}"'
  Sleep 2000
  nsExec::ExecToLog 'sc delete "${SERVICE_NAME}"'
  Sleep 1000

  ; Install files
  SetOutPath "$INSTDIR"
  File "${RELEASE_DIR}\${PRODUCT_EXE}"
  File "${RELEASE_DIR}\StreamGuardTray.exe"
  File "${RELEASE_DIR}\tray_icon.ico"
  File "${RELEASE_DIR}\LICENSE"
  File "${RELEASE_DIR}\CHANGELOG.md"
  File "${RELEASE_DIR}\FAQ.md"
  File "${RELEASE_DIR}\USER_GUIDE.md"
  File "${RELEASE_DIR}\SECURITY.md"

  ; Register Windows Service
  ; SECURITY: binPath value is double-quoted to prevent unquoted service path privilege escalation
  nsExec::ExecToLog 'sc create "${SERVICE_NAME}" binPath= "\"$INSTDIR\${PRODUCT_EXE}\"" DisplayName= "${PRODUCT_NAME}" start= auto'
  nsExec::ExecToLog 'sc description "${SERVICE_NAME}" "Automates Mullvad VPN toggling, DNS leak protection, and security monitoring for VTubers."'
  nsExec::ExecToLog 'sc start "${SERVICE_NAME}"'

  ; Create desktop shortcut
  CreateShortcut "$DESKTOP\StreamGuard.lnk" "$INSTDIR\${PRODUCT_EXE}" "" "$INSTDIR\tray_icon.ico" 0

  ; Create Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\StreamGuard"
  CreateShortcut "$SMPROGRAMS\StreamGuard\StreamGuard.lnk" "$INSTDIR\${PRODUCT_EXE}" "" "$INSTDIR\tray_icon.ico" 0
  CreateShortcut "$SMPROGRAMS\StreamGuard\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

  ; Register tray app to auto-start on user login
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "StreamGuardTray" '"$INSTDIR\StreamGuardTray.exe"'

  ; Launch tray app immediately after install
  Exec '"$INSTDIR\StreamGuardTray.exe"'

  ; Write registry keys
  WriteRegStr HKLM "Software\GearLightLabs\StreamGuard" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\GearLightLabs\StreamGuard" "Version" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard" "DisplayIcon" "$INSTDIR\tray_icon.ico"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard" "URLInfoAbout" "${PRODUCT_URL}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard" "NoRepair" 1

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

SectionEnd

Section "Documentation" SecDocs
  SetOutPath "$INSTDIR\docs"
  File "${RELEASE_DIR}\USER_GUIDE.md"
  File "${RELEASE_DIR}\FAQ.md"
  File "${RELEASE_DIR}\SECURITY.md"
SectionEnd

;--------------------------------
; Section descriptions

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "The StreamGuard core files and Windows Service registration. Required."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDocs} "Documentation files including User Guide, FAQ, and Security Policy."
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

  ; SECURITY FIX: Strip deny ACEs from ProgramData folder before deletion.
  ; The service applies restrictive ACLs to protect hmac_seed.bin and status.json.
  ; Without stripping these, the uninstaller cannot delete the folder.
  nsExec::ExecToLog 'icacls "$APPDATA\..\..\ProgramData\StreamGuard" /remove:d *S-1-1-0 /t /c'
  nsExec::ExecToLog 'icacls "$APPDATA\..\..\ProgramData\StreamGuard" /remove:d *S-1-5-11 /t /c'
  nsExec::ExecToLog 'icacls "$APPDATA\..\..\ProgramData\StreamGuard" /remove:d *S-1-5-32-545 /t /c'
  nsExec::ExecToLog 'icacls "$APPDATA\..\..\ProgramData\StreamGuard" /grant *S-1-5-32-544:F /t /c'
  RMDir /r "$APPDATA\..\..\ProgramData\StreamGuard"

  ; Delete installed files
  Delete /REBOOTOK "$INSTDIR\${PRODUCT_EXE}"
  Delete /REBOOTOK "$INSTDIR\StreamGuardTray.exe"
  Delete "$INSTDIR\tray_icon.ico"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\CHANGELOG.md"
  Delete "$INSTDIR\FAQ.md"
  Delete "$INSTDIR\USER_GUIDE.md"
  Delete "$INSTDIR\SECURITY.md"
  Delete "$INSTDIR\docs\USER_GUIDE.md"
  Delete "$INSTDIR\docs\FAQ.md"
  Delete "$INSTDIR\docs\SECURITY.md"
  Delete "$INSTDIR\Uninstall.exe"

  ; Remove directories
  RMDir "$INSTDIR\docs"
  RMDir /r "$INSTDIR"

  ; Remove tray auto-start registry entry and kill tray process
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "StreamGuardTray"
  nsExec::ExecToLog 'taskkill /IM StreamGuardTray.exe /F'
  Sleep 500

  ; Remove shortcuts
  Delete "$DESKTOP\StreamGuard.lnk"
  Delete "$SMPROGRAMS\StreamGuard\StreamGuard.lnk"
  Delete "$SMPROGRAMS\StreamGuard\Uninstall.lnk"
  RMDir "$SMPROGRAMS\StreamGuard"

  ; Remove registry keys
  DeleteRegKey HKLM "Software\GearLightLabs\StreamGuard"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard"

  MessageBox MB_ICONINFORMATION|MB_OK "StreamGuard has been uninstalled.$\r$\n$\r$\nEverything has been cleaned up.$\r$\n$\r$\nNote: your audit logs at C:\ProgramData\StreamGuard\Logs\ were kept on purpose. Those are your records.$\r$\n$\r$\nThanks for using it. Stay safe.$\r$\n- Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com"

SectionEnd
