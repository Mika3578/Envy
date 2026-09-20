@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem Windows wrapper for scripts\bootstrap-vcpkg.ps1 (VS developers, cmd.exe).
rem Prefer PowerShell 7 when present; fall back to Windows PowerShell 5.1.
rem Delayed expansion is required so the child exit code is read after pwsh
rem returns (plain %ERRORLEVEL% inside parentheses expands too early).

set "SCRIPT=%~dp0bootstrap-vcpkg.ps1"
where pwsh >nul 2>&1
if !ERRORLEVEL!==0 (
	pwsh -NoProfile -File "%SCRIPT%" %*
	exit /b !ERRORLEVEL!
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
exit /b !ERRORLEVEL!
