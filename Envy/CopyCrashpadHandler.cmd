@echo off
rem Copy crashpad_handler.exe (and optional crashpad_wer*.dll) next to Envy.exe.
rem Prefer the configuration-matching vcpkg tool, never a recursive first-match
rem (dir /s /b hits debug\tools first and would ship a Debug handler with
rem Release Envy.exe).
rem vcpkg crashpad 2026-07-02 installs via vcpkg_copy_tools to
rem   vcpkg_installed\<triplet>\tools\crashpad_handler.exe
rem (debug: debug\tools\crashpad_handler.exe). Also accept tools\crashpad\.
rem %1 - $(ConfigurationName)
rem %2 - $(PlatformName)
setlocal EnableExtensions
set "CONFIG=%~1"
set "PLATFORM=%~2"
if "%CONFIG%"=="" (
	echo error: CopyCrashpadHandler.cmd requires ConfigurationName
	exit /b 1
)
if "%PLATFORM%"=="" (
	echo error: CopyCrashpadHandler.cmd requires PlatformName
	exit /b 1
)

set "TRIPLET=x86-windows-static"
if /I "%PLATFORM%"=="x64" set "TRIPLET=x64-windows-static"

set "SCRIPTDIR=%~dp0"
set "ROOT=%SCRIPTDIR%.."
set "DEST=%SCRIPTDIR%%CONFIG% %PLATFORM%"
if not exist "%DEST%" mkdir "%DEST%"

set "SEARCHROOT=%ROOT%\vcpkg_installed\%TRIPLET%"
if not exist "%SEARCHROOT%" (
	echo error: vcpkg_installed\%TRIPLET% not found.
	echo Visual Studio does not restore the root vcpkg.json manifest before PreBuildEvent.
	echo CI runs "vcpkg install --triplet=%TRIPLET%" first; a fresh local checkout must do the same.
	echo From the repository root run:
	echo   scripts\bootstrap-vcpkg.cmd -Triplet %TRIPLET%
	echo or:
	echo   vcpkg install --triplet=%TRIPLET%
	echo Requires a bootstrapped vcpkg ^(VCPKG_ROOT, VCPKG_INSTALLATION_ROOT, .\vcpkg, or PATH^).
	exit /b 1
)

if /I "%CONFIG%"=="Debug" (
	set "CAND1=%SEARCHROOT%\debug\tools\crashpad_handler.exe"
	set "CAND2=%SEARCHROOT%\debug\tools\crashpad\crashpad_handler.exe"
) else (
	set "CAND1=%SEARCHROOT%\tools\crashpad_handler.exe"
	set "CAND2=%SEARCHROOT%\tools\crashpad\crashpad_handler.exe"
)

set "HANDLER="
if exist "%CAND1%" set "HANDLER=%CAND1%"
if not defined HANDLER if exist "%CAND2%" set "HANDLER=%CAND2%"
if not defined HANDLER (
	echo error: crashpad_handler.exe not found at:
	echo   %CAND1%
	echo   %CAND2%
	echo error: Crashpad is required. From the repository root run:
	echo   scripts\bootstrap-vcpkg.cmd -Triplet %TRIPLET%
	echo or:
	echo   vcpkg install --triplet=%TRIPLET%
	exit /b 1
)

for %%I in ("%HANDLER%") do set "HANDLERDIR=%%~dpI"

copy /b /y "%HANDLER%" "%DEST%\crashpad_handler.exe" >nul
if errorlevel 1 (
	echo error: failed to copy "%HANDLER%" to "%DEST%\crashpad_handler.exe"
	exit /b 1
)
echo Copied "%HANDLER%" to "%DEST%\crashpad_handler.exe"
for %%F in ("%HANDLERDIR%crashpad_wer*.dll") do (
	if exist "%%~fF" copy /b /y "%%~fF" "%DEST%\" >nul
)
exit /b 0
