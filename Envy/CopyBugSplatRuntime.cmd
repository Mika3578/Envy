@echo off
rem Copy BugSplat x64 runtime files next to Envy.exe.
rem %1 - ConfigurationName (Debug|Release)
rem %2 - PlatformName (must be x64)
rem %3 - Active VCToolsInstallDir (from MSBuild)
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
set "PS_EXE="
where pwsh >nul 2>&1 && set "PS_EXE=pwsh"
if not defined PS_EXE where powershell >nul 2>&1 && set "PS_EXE=powershell"
if not defined PS_EXE (
	echo error: pwsh or powershell is required to copy MSVC runtime DLLs for BugSplat /MD binaries.
	exit /b 1
)
set "VC_TOOLS=%~3"
if not defined VC_TOOLS set "VC_TOOLS=%VCToolsInstallDir%"
rem A trailing backslash turns the closing quote into an escaped quote for the
rem child's command-line parser, so it swallows -DisableToolchainFallback.
if "%VC_TOOLS:~-1%"=="\" set "VC_TOOLS=%VC_TOOLS:~0,-1%"
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0CopyBugSplatVcRuntime.ps1" -Configuration "%~1" -Platform "%~2" -VcToolsInstallDir "%VC_TOOLS%" -DisableToolchainFallback
if errorlevel 1 exit /b 1
exit /b 0
