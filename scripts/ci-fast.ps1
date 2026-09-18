#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
  Fast local quality gate for Envy (pre-push / pre-commit style).

.DESCRIPTION
  Runs inexpensive checks only. Prefer this before every push.
  For the full local analogue of GitHub PR gates, use .\scripts\ci-verify.ps1

.NOTES
  Exit code 0 = pass. Non-zero = fail.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = git rev-parse --show-toplevel 2>$null
if (-not $root) { throw 'Not inside a git repository.' }
Set-Location $root

Write-Host '== Envy ci-fast ==' -ForegroundColor Cyan

# Differential format check when clang-format is available (optional locally).
$clangFormat = Get-Command clang-format -ErrorAction SilentlyContinue
if ($clangFormat) {
	Write-Host '-- clang-format --dry-run (changed C/C++ under Envy/)' -ForegroundColor DarkCyan
	$base = 'origin/develop'
	git rev-parse --verify $base 2>$null | Out-Null
	if ($LASTEXITCODE -ne 0) { $base = 'develop' }
	$files = @(git diff --name-only --diff-filter=ACMR "$base..." -- 'Envy/*.cpp' 'Envy/*.h' 'TorrentEnvy/*.cpp' 'TorrentEnvy/*.h' 'HashLib/*.cpp' 'HashLib/*.h' 2>$null)
	foreach ($f in $files) {
		if (-not (Test-Path -LiteralPath $f)) { continue }
		& clang-format --dry-run --Werror $f
		if ($LASTEXITCODE -ne 0) {
			Write-Error "clang-format failed: $f"
			exit 1
		}
	}
} else {
	Write-Host '-- clang-format not on PATH (skip local format; CI Format Check still runs)' -ForegroundColor DarkYellow
}

# Sanity: no obvious conflict markers in tracked changes
$dirty = @(git diff --name-only HEAD)
foreach ($f in $dirty) {
	if (-not (Test-Path -LiteralPath $f)) { continue }
	if (Select-String -Path $f -Pattern '^(<<<<<<<|=======|>>>>>>>)' -Quiet) {
		Write-Error "Conflict marker in $f"
		exit 1
	}
}

Write-Host 'ci-fast OK' -ForegroundColor Green
exit 0
