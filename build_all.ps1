# Build Debug/Release x Win32/x64 for Envy using the authoritative MSBuild flags.
# Requires Visual Studio 2026 (toolset v145) and vcpkg (manifest mode).
# Usage: .\build_all.ps1
# Optional: .\build_all.ps1 -Configuration Release -Platform x64

[CmdletBinding()]
param(
	[ValidateSet('Debug', 'Release', 'All')]
	[string]$Configuration = 'All',

	[ValidateSet('Win32', 'x64', 'All')]
	[string]$Platform = 'All'
)

$ErrorActionPreference = 'Stop'

$solution = Join-Path $PSScriptRoot 'Visual Studio\Envy.sln'
if (-not (Test-Path $solution)) {
	throw "Solution not found: $solution"
}

function Find-MSBuild {
	$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
	if (Test-Path $vswhere) {
		$path = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
			-find 'MSBuild\**\Bin\amd64\MSBuild.exe' 2>$null |
			Select-Object -First 1
		if ($path) { return $path }
	}
	$fallback = 'C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe'
	if (Test-Path $fallback) { return $fallback }
	throw 'MSBuild.exe not found. Install Visual Studio 2026 with MSBuild.'
}

$msbuild = Find-MSBuild
Write-Host "Using MSBuild: $msbuild"

$configs = if ($Configuration -eq 'All') { @('Debug', 'Release') } else { @($Configuration) }
$platforms = if ($Platform -eq 'All') { @('Win32', 'x64') } else { @($Platform) }

$failed = @()
foreach ($cfg in $configs) {
	foreach ($plat in $platforms) {
		Write-Host "`n=== Building $cfg|$plat ===" -ForegroundColor Cyan
		$args = @(
			$solution,
			'/m',
			"/p:Configuration=$cfg",
			"/p:Platform=$plat",
			'/p:PlatformToolset=v145',
			'/p:WindowsTargetPlatformVersion=10.0',
			'/p:VcpkgEnableManifest=true',
			'/p:VcpkgTriplet=' + $(if ($plat -eq 'x64') { 'x64-windows-static' } else { 'x86-windows-static' }),
			'/verbosity:minimal'
		)
		& $msbuild @args
		if ($LASTEXITCODE -ne 0) {
			Write-Host "FAILED: $cfg|$plat (exit $LASTEXITCODE)" -ForegroundColor Red
			$failed += "$cfg|$plat"
		} else {
			Write-Host "OK: $cfg|$plat" -ForegroundColor Green
		}
	}
}

if ($failed.Count -gt 0) {
	Write-Host "`nFailed builds: $($failed -join ', ')" -ForegroundColor Red
	exit 1
}

Write-Host "`nAll requested builds completed successfully." -ForegroundColor Green
