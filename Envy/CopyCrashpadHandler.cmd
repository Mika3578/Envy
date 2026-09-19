@echo off
rem Copy crashpad_handler.exe (and optional crashpad_wer*.dll) next to Envy.exe.
rem %1 - $(ConfigurationName)
rem %2 - $(PlatformName)
setlocal EnableExtensions
set "CONFIG=%~1"
set "PLATFORM=%~2"
if "%CONFIG%"=="" exit /b 0
if "%PLATFORM%"=="" exit /b 0

set "TRIPLET=x86-windows-static"
if /I "%PLATFORM%"=="x64" set "TRIPLET=x64-windows-static"

set "SCRIPTDIR=%~dp0"
set "ROOT=%SCRIPTDIR%.."
set "DEST=%SCRIPTDIR%%CONFIG% %PLATFORM%"
if not exist "%DEST%" mkdir "%DEST%"

set "SEARCHROOT=%ROOT%\vcpkg_installed\%TRIPLET%"
if not exist "%SEARCHROOT%" exit /b 0

set "HANDLER="
for /f "delims=" %%F in ('dir /s /b "%SEARCHROOT%\crashpad_handler.exe" 2^>nul') do (
	set "HANDLER=%%F"
	goto :found
)
echo Note: crashpad_handler.exe not found under vcpkg_installed\%TRIPLET%
exit /b 0

:found
copy /b /y "%HANDLER%" "%DEST%\crashpad_handler.exe" >nul
for /f "delims=" %%F in ('dir /s /b "%SEARCHROOT%\crashpad_wer*.dll" 2^>nul') do (
	copy /b /y "%%F" "%DEST%\" >nul
)
exit /b 0
