#!/usr/bin/env pwsh
# After MSBuild: ensure BugSplat /MD runtime PE dependencies are present next to Envy.exe (x64).
param(
	[string]$OutputDir,
	[string]$VcToolsInstallDir,
	[switch]$DisableToolchainFallback
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot (Join-Path 'lib' 'EnvyVcTools.psm1')
Import-Module $modulePath -Force

if (-not $OutputDir) { throw 'OutputDir required (e.g. Envy/Release x64)' }
if (-not (Test-Path -LiteralPath $OutputDir)) { throw "Output directory not found: $OutputDir" }

$monitor = Join-Path $OutputDir 'BugSplatMonitor.exe'
if (-not (Test-Path -LiteralPath $monitor)) {
	Write-Host "verify-bugsplat-output-layout: no BugSplatMonitor.exe under $OutputDir; skip."
	exit 0
}

$dumpbin = Get-EnvyDumpBinPath -VcToolsInstallDir $VcToolsInstallDir -DisableFallback:$DisableToolchainFallback
if (-not $dumpbin) {
	throw @"
dumpbin.exe was not found; cannot verify BugSplatMonitor.exe MSVC dependents under $OutputDir.
Ensure the Windows CI runner or local build uses Visual Studio C++ tools (VCToolsInstallDir).
"@
}

$leaf = Split-Path -Leaf $OutputDir
$configuration = ($leaf -split '\s+', 2)[0]
$platform = ($leaf -split '\s+', 2)[1]
$needed = Get-BugSplatOutputRequiredDlls -MonitorPath $monitor -DumpBinPath $dumpbin -Configuration $configuration -Platform $platform
$missing = @()
foreach ($name in $needed) {
	$path = Join-Path $OutputDir $name
	if (-not (Test-Path -LiteralPath $path)) {
		$missing += $name
	}
}
if ($missing.Count -gt 0) {
	throw "BugSplatMonitor.exe requires $($missing -join ', ') next to Envy.exe under $OutputDir. Ensure Envy/CopyBugSplatRuntime.cmd ran (post-build) and CopyBugSplatVcRuntime.ps1 copied MSVC redist DLLs."
}
Write-Host "verify-bugsplat-output-layout: OK ($OutputDir)"
