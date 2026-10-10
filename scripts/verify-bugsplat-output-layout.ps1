#!/usr/bin/env pwsh
# After MSBuild: ensure BugSplat /MD runtime PE dependencies are present next to Envy.exe (x64).
param(
	[string]$OutputDir,
	[string]$VcToolsInstallDir,
	[ValidateSet("Debug", "Release")][string]$Configuration,
	[ValidateSet("x64")][string]$Platform,
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
	throw "Missing required BugSplat runtime: BugSplatMonitor.exe under $OutputDir"
}

$dumpbin = Get-EnvyDumpBinPath -VcToolsInstallDir $VcToolsInstallDir -DisableFallback:$DisableToolchainFallback
if (-not $dumpbin) {
	throw @"
dumpbin.exe was not found; cannot verify BugSplatMonitor.exe MSVC dependents under $OutputDir.
Ensure the Windows CI runner or local build uses Visual Studio C++ tools (VCToolsInstallDir).
"@
}

foreach ($name in @('BugSplatWer.dll', 'BugSplatRc.dll')) {
	if (-not (Test-Path -LiteralPath (Join-Path $OutputDir $name) -PathType Leaf)) {
		throw "Missing required BugSplat runtime: $name under $OutputDir"
	}
}
$layout = @((Split-Path -Leaf $OutputDir) -split '\s+', 2)
if (-not $Configuration -and $layout.Count -eq 2) { $Configuration = $layout[0] }
if (-not $Platform -and $layout.Count -eq 2) { $Platform = $layout[1] }
if ($Configuration -notin @('Debug', 'Release') -or $Platform -ne 'x64') {
	throw 'Specify Configuration and Platform for an output directory not named Debug x64 or Release x64'
}
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
