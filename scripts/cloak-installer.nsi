; NSIS installer for cloak - cross-built from macOS via Homebrew's
; makensis, never run on real Windows during development. Verify the
; output is at least a well-formed PE binary before trusting it further;
; see scripts/package-windows.sh.
;
; Installs cloak.exe and cloak-tray.exe to Program Files, adds a Start
; Menu shortcut for the tray app, and registers an uninstaller. It does
; NOT wire auto-start itself - that's `cloak service install`'s job
; (a login Run-key entry), run manually after installing.

!define APP_NAME "cloak"
!define COMPANY "cloak"
!define VERSION "${CLOAK_VERSION}"
!define INSTALL_DIR "$PROGRAMFILES64\cloak"

Name "${APP_NAME}"
OutFile "${OUT_FILE}"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel user

Page directory
Page instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  File "${BUILD_DIR}\cloak.exe"
  File "${BUILD_DIR}\cloak-tray.exe"

  CreateDirectory "$SMPROGRAMS\cloak"
  CreateShortcut "$SMPROGRAMS\cloak\cloak-tray.lnk" "$INSTDIR\cloak-tray.exe"
  CreateShortcut "$SMPROGRAMS\cloak\Uninstall cloak.lnk" "$INSTDIR\Uninstall.exe"

  WriteUninstaller "$INSTDIR\Uninstall.exe"

  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\cloak" "DisplayName" "cloak"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\cloak" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\cloak" "DisplayVersion" "${VERSION}"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\cloak.exe"
  Delete "$INSTDIR\cloak-tray.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\cloak\cloak-tray.lnk"
  Delete "$SMPROGRAMS\cloak\Uninstall cloak.lnk"
  RMDir "$SMPROGRAMS\cloak"

  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\cloak"
SectionEnd
