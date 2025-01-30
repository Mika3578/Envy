; Define constants
!define TITLE "Envy Search Export Plugin"
!define VERSION "1.0.0.0"
!define COMPANY "Envy"
!define FILENAME "x64\SearchExport_Setup64_${VERSION}.exe"
!define COPYRIGHT "© 2009 Nikolay Raspopov"
!define UNINST "SearchExport_Uninst.exe"

Name "${TITLE}"

; Version Information
VIProductVersion "${VERSION}"
VIAddVersionKey ProductName "${TITLE}"
VIAddVersionKey ProductVersion "${VERSION}"
VIAddVersionKey OriginalFilename "${FILENAME}"
VIAddVersionKey FileDescription "${TITLE}"
VIAddVersionKey FileVersion "${VERSION}"
VIAddVersionKey CompanyName "${COMPANY}"
VIAddVersionKey LegalCopyright "${COPYRIGHT}"

; Installer settings
CRCCheck On
XPStyle On
BrandingText "Envy Development Team"
SetOverwrite On
OutFile "${FILENAME}"
InstallDir "$PROGRAMFILES64\Envy"
InstallDirRegKey HKCU "Software\Envy\Envy" "Path"
ShowInstDetails show
ShowUninstDetails show
RequestExecutionLevel admin
SetCompressor /SOLID lzma

Var STARTMENU_FOLDER

; Include Modern UI
!include "MUI.nsh"

; Modern UI settings
!define MUI_ABORTWARNING
!define MUI_HEADERIMAGE
!define MUI_ICON "..\..\Installer\Res\Install.ico"
!define MUI_UNICON "..\..\Installer\Res\Uninstall.ico"
!define MUI_HEADERIMAGE_BITMAP "..\..\Installer\Res\CornerLogo.bmp"
!define MUI_HEADERIMAGE_BITMAP_NOSTRETCH
!define MUI_HEADERIMAGE_UNBITMAP "..\..\Installer\Res\CornerLogo.bmp"
!define MUI_HEADERIMAGE_UNBITMAP_NOSTRETCH
!define MUI_WELCOMEFINISHPAGE_BITMAP "..\..\Installer\Res\Sidebar.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "..\..\Installer\Res\Sidebar.bmp"
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "Envy"
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKCU"
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\Envy"
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\Installer\license\default.rtf"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_STARTMENU Application $STARTMENU_FOLDER
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Language
!insertmacro MUI_LANGUAGE "English"

; .onInit function
Function .onInit
    SetShellVarContext all
    SetRegView 64

    ; Disable second run
    System::Call 'kernel32::CreateMutexA(i 0, i 0, t "${TITLE}") i .r1 ?e'
    Pop $R0
    StrCmp $R0 0 +3
    MessageBox MB_ICONSTOP|MB_OK "Setup already running."
    Quit
FunctionEnd

; un.onInit function
Function un.onInit
    SetShellVarContext all
    SetRegView 64

    ; Disable second run
    System::Call 'kernel32::CreateMutexA(i 0, i 0, t "${TITLE}") i .r1 ?e'
    Pop $R0
    StrCmp $R0 0 +3
    MessageBox MB_ICONSTOP|MB_OK "Setup already running."
    Quit
FunctionEnd

; Install section
Section "Install"
    SetOutPath $INSTDIR

    ; Close Envy before installation
    DetailPrint "Checking for Envy..."
    System::Call 'kernel32::CreateMutexA(i 0, i 0, t "Global\Envy") i .r1 ?e'
    Pop $R0
    StrCmp $R0 0 +3
    MessageBox MB_ICONSTOP|MB_OK "Please close Envy and run setup again."
    Quit

    ; Install plugin
    File /r "Templates"
    File "Release x64\SearchExport.dll"
    RegDLL "$INSTDIR\SearchExport.dll"

    ; Install Uninstaller
    !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    CreateDirectory "$SMPROGRAMS\$STARTMENU_FOLDER"
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\Uninstall ${TITLE}.lnk" "$INSTDIR\${UNINST}" "" "$INSTDIR\${UNINST}" 0
    !insertmacro MUI_STARTMENU_WRITE_END
    WriteRegStr HKCU "Software\Envy\Envy" "Path" $INSTDIR
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}" "DisplayName" "${TITLE}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}" "UninstallString" "$INSTDIR\${UNINST}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}" "DisplayIcon" "$INSTDIR\SearchExport.dll,0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}" "Publisher" "${COMPANY}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}" "NoRepair" 1
    WriteUninstaller "${UNINST}"
SectionEnd

; Uninstall section
Section "Uninstall"
    SetOutPath $TEMP

    ; Close Envy before uninstallation
    DetailPrint "Checking for Envy..."
    System::Call 'kernel32::CreateMutexA(i 0, i 0, t "Global\Envy") i .r1 ?e'
    Pop $R0
    StrCmp $R0 0 +3
    MessageBox MB_ICONSTOP|MB_OK "Please close Envy and run setup again."
    Quit

    ; Uninstall plugin
    UnRegDLL "$INSTDIR\SearchExport.dll"
    Delete "$INSTDIR\SearchExport.dll"
    RmDir /r "$INSTDIR\Templates"

    ; Uninstall uninstaller
    !insertmacro MUI_STARTMENU_GETFOLDER Application $STARTMENU_FOLDER
    Delete "$SMPROGRAMS\$STARTMENU_FOLDER\Uninstall ${TITLE}.lnk"
    RmDir "$SMPROGRAMS\$STARTMENU_FOLDER"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}"
    Delete "$INSTDIR\${UNINST}"
    RmDir "$INSTDIR"
SectionEnd

!appendfile "SearchExport.trg" "[${__TIMESTAMP__}] ${TITLE} ${VERSION} ${FILENAME}$\n"
