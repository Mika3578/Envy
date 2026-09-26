@echo off
rem Copy BugSplat x64 runtime files next to Envy.exe.
rem %1 - ConfigurationName (Debug|Release)
rem %2 - PlatformName (must be x64)
setlocal EnableExtensions
if /I not "%~2"=="x64" exit /b 0
if "%~1"=="" exit /b 1

set "ROOT=%~dp0..\ThirdParty\BugSplat\x64\%~1\bin"
set "DEST=%~dp0%~1 %~2"
if not exist "%DEST%" mkdir "%DEST%"

if not exist "%ROOT%\BugSplatMonitor.exe" (
	echo error: BugSplat runtime not found under "%ROOT%"
	echo Run scripts\import-bugsplat-sdk.ps1 from the official BugSplat native SDK.
	exit /b 1
)

copy /b /y "%ROOT%\BugSplatMonitor.exe" "%DEST%\" >nul
if errorlevel 1 exit /b 1
for %%F in (BugSplatWer.dll BugSplatRc.dll) do (
	if not exist "%ROOT%\%%F" (
		echo error: required BugSplat runtime "%%F" not found under "%ROOT%"
		exit /b 1
	)
	copy /b /y "%ROOT%\%%F" "%DEST%\" >nul
	if errorlevel 1 exit /b 1
)
echo Copied BugSplat runtime from "%ROOT%" to "%DEST%"
exit /b 0
