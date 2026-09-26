#!/usr/bin/env pwsh
# After MSBuild: ensure BugSplat /MD runtime PE dependencies are present next to Envy.exe (x64).
param(
	[string]$OutputDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $OutputDir) { throw 'OutputDir required (e.g. Envy/Release x64)' }
if (-not (Test-Path -LiteralPath $OutputDir)) { throw "Output directory not found: $OutputDir" }

$monitor = Join-Path $OutputDir 'BugSplatMonitor.exe'
if (-not (Test-Path -LiteralPath $monitor)) {
	Write-Host "verify-bugsplat-output-layout: no BugSplatMonitor.exe under $OutputDir; skip."
	exit 0
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
	Write-Warning 'vswhere not found; skipping BugSplat MSVC dependency layout check.'
	exit 0
}
$install = (& $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -as [string]
if (-not $install) {
	Write-Warning 'VS C++ tools not found; skipping BugSplat MSVC dependency layout check.'
	exit 0
}
$dumpbin = Get-ChildItem -Path (Join-Path $install 'VC\Tools\MSVC') -Recurse -Filter 'dumpbin.exe' -ErrorAction SilentlyContinue |
	Where-Object { $_.FullName -match '\\Hostx64\\x64\\dumpbin\.exe$' } |
	Select-Object -First 1
if (-not $dumpbin) {
	Write-Warning 'dumpbin not found; skipping BugSplat MSVC dependency layout check.'
	exit 0
}

$depOut = & $dumpbin.FullName /nologo /dependents $monitor 2>&1 | Out-String
$missing = @()
foreach ($name in @('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll', 'msvcp140_1.dll', 'msvcp140_2.dll')) {
	if ($depOut -match "(?im)^\s+$name\s*$") {
		$path = Join-Path $OutputDir $name
		if (-not (Test-Path -LiteralPath $path)) {
			$missing += $name
		}
	}
}
if ($missing.Count -gt 0) {
	throw "BugSplatMonitor.exe requires $($missing -join ', ') next to Envy.exe under $OutputDir. Ensure Envy/CopyBugSplatRuntime.cmd ran (post-build) and CopyBugSplatVcRuntime.ps1 copied MSVC redist DLLs."
}
Write-Host "verify-bugsplat-output-layout: OK ($OutputDir)"
