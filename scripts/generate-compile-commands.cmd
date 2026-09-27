@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem Windows wrapper for scripts\generate-compile-commands.ps1 (cmd.exe / VS developers).
rem Requires PowerShell 7 (pwsh).

set "SCRIPT=%~dp0generate-compile-commands.ps1"
where pwsh >nul 2>&1
if !ERRORLEVEL!==0 (
	pwsh -NoProfile -File "%SCRIPT%" %*
	exit /b !ERRORLEVEL!
)
echo ERROR: pwsh (PowerShell 7) is required. Install from https://aka.ms/powershell
exit /b 1
