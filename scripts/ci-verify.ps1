#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
  Local verification approximating Mika3578/Envy GitHub PR merge gates.

.DESCRIPTION
  Default: ci-fast + Envy Release x64 + EnvyTests Release x64 + run EnvyTests x64.
  -Full: also Envy Release Win32 + EnvyTests Release Win32 + run EnvyTests Win32,
  and requires clang-format on PATH (ci-fast alone may only warn if missing).

  This is the Windows-native counterpart of a portable ./ci/verify.sh. It does not
  replace GitHub-required checks (CodeQL, Sonar, gitleaks, PR Gate).

.EXAMPLE
  .\scripts\ci-verify.ps1
  .\scripts\ci-verify.ps1 -Full
#>
[CmdletBinding()]
param(
	[switch]$Full,
	[string]$Configuration = 'Release',
	[string]$Msbuild = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = git rev-parse --show-toplevel 2>$null
if (-not $root) { throw 'Not inside a git repository.' }
Set-Location $root

function Resolve-MsBuild {
	param([string]$Preferred)
	if ($Preferred -and (Test-Path -LiteralPath $Preferred)) { return $Preferred }
	$candidates = @(
		'C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe',
		'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe',
		'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
	)
	foreach ($c in $candidates) {
		if (Test-Path -LiteralPath $c) { return $c }
	}
	$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
	if (Test-Path -LiteralPath $vswhere) {
		$found = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\amd64\MSBuild.exe' 2>$null | Select-Object -First 1
		if ($found) { return $found }
	}
	throw 'MSBuild.exe not found. Install VS 2026/2022 or pass -Msbuild.'
}

function Invoke-Step {
	param([string]$Name, [scriptblock]$Body)
	Write-Host ""
	Write-Host "== $Name ==" -ForegroundColor Cyan
	& $Body
	if ($LASTEXITCODE -ne 0) {
		throw "Step failed: $Name (exit $LASTEXITCODE)"
	}
}

function Resolve-EnvyTestsExe {
	param(
		[string]$Platform,
		[string]$Config
	)
	$candidates = @(
		(Join-Path $root "tests\$Config $Platform\EnvyTests.exe"),
		(Join-Path $root "tests\Release $Platform\EnvyTests.exe")
	)
	foreach ($p in $candidates) {
		if (Test-Path -LiteralPath $p) { return $p }
	}
	throw "EnvyTests.exe not found for $Config $Platform. Tried:`n  $($candidates -join "`n  ")"
}

$msbuild = Resolve-MsBuild -Preferred $Msbuild
Write-Host "MSBuild: $msbuild" -ForegroundColor DarkGray
Write-Host "Configuration: $Configuration  Full=$Full" -ForegroundColor DarkGray

if ($Full) {
	$clangFormat = Get-Command clang-format -ErrorAction SilentlyContinue
	if (-not $clangFormat) {
		throw 'ci-verify -Full requires clang-format on PATH (or run Format Check in CI). ci-fast may warn; Full must not report OK without a real format gate.'
	}
}

# Fast path first
Invoke-Step 'ci-fast' {
	& "$root\scripts\ci-fast.ps1"
	if ($null -eq $LASTEXITCODE) { $global:LASTEXITCODE = 0 }
}

$common = @(
	'/m',
	"/p:Configuration=$Configuration",
	'/p:PlatformToolset=v145',
	'/p:WindowsTargetPlatformVersion=10.0',
	'/p:VcpkgEnableManifest=true',
	'/v:minimal',
	'/nologo'
)

Invoke-Step 'Envy Release x64' {
	& $msbuild 'Visual Studio\Envy.sln' @common '/t:Envy' '/p:Platform=x64' '/p:VcpkgTriplet=x64-windows-static'
}

Invoke-Step 'EnvyTests Release x64' {
	& $msbuild 'tests\EnvyTests.vcxproj' @common '/p:Platform=x64'
}

$testsX64 = Resolve-EnvyTestsExe -Platform 'x64' -Config $Configuration
Invoke-Step 'Run EnvyTests x64' {
	& $testsX64
}

if ($Full) {
	Invoke-Step 'Envy Release Win32' {
		& $msbuild 'Visual Studio\Envy.sln' @common '/t:Envy' '/p:Platform=Win32' '/p:VcpkgTriplet=x86-windows-static'
	}

	Invoke-Step 'EnvyTests Release Win32' {
		& $msbuild 'tests\EnvyTests.vcxproj' @common '/p:Platform=Win32'
	}

	$testsWin32 = Resolve-EnvyTestsExe -Platform 'Win32' -Config $Configuration
	Invoke-Step 'Run EnvyTests Win32' {
		& $testsWin32
	}
}

Write-Host ''
Write-Host 'ci-verify OK (local MSVC/tests). Still run GitHub PR checks before merge.' -ForegroundColor Green
exit 0
