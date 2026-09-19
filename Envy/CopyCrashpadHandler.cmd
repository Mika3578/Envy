@echo off
rem Copy crashpad_handler.exe (and optional crashpad_wer*.dll) next to Envy.exe.
rem Use the configuration-matching vcpkg layout. A recursive dir /s /b of
rem vcpkg_installed\<triplet> hits debug\tools\crashpad first and would ship
rem a Debug handler with Release Envy.exe.
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
	echo error: vcpkg_installed\%TRIPLET% not found. From the repository root run:
	echo   vcpkg install --triplet=%TRIPLET%
	exit /b 1
)

set "HANDLERDIR=%SEARCHROOT%\tools\crashpad"
if /I "%CONFIG%"=="Debug" set "HANDLERDIR=%SEARCHROOT%\debug\tools\crashpad"
set "HANDLER=%HANDLERDIR%\crashpad_handler.exe"
if not exist "%HANDLER%" (
	echo error: crashpad_handler.exe not found at "%HANDLER%"
	echo error: from the repository root run: vcpkg install --triplet=%TRIPLET%
	exit /b 1
)

copy /b /y "%HANDLER%" "%DEST%\crashpad_handler.exe" >nul
if errorlevel 1 (
	echo error: failed to copy "%HANDLER%" to "%DEST%\crashpad_handler.exe"
	exit /b 1
)
echo Copied "%HANDLER%" to "%DEST%\crashpad_handler.exe"
for %%F in ("%HANDLERDIR%\crashpad_wer*.dll") do (
	if exist "%%~fF" copy /b /y "%%~fF" "%DEST%\" >nul
)
exit /b 0
