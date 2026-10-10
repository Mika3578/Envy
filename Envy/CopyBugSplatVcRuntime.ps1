#!/usr/bin/env pwsh
# Copy MSVC/UCRT DLLs required by BugSplat /MD PEs next to Envy.exe (x64 only).
param(
	[string]$Configuration,
	[string]$Platform,
	[string]$VcToolsInstallDir,
	[string]$DestOverride,
	[switch]$DisableToolchainFallback
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = (Resolve-Path -LiteralPath (
	Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts') (
		Join-Path 'lib' 'EnvyVcTools.psm1'
	)
)).Path
Import-Module $modulePath -Force

if ($Platform -ne 'x64') { exit 0 }
if (-not $Configuration) { throw 'Configuration required' }

$dest = if ($DestOverride) { $DestOverride } else { Join-Path $PSScriptRoot "$Configuration $Platform" }
if (-not (Test-Path -LiteralPath $dest)) { exit 0 }

$monitor = Join-Path $dest 'BugSplatMonitor.exe'
if (-not (Test-Path -LiteralPath $monitor)) { exit 0 }

$dumpbin = Get-EnvyDumpBinPath -VcToolsInstallDir $VcToolsInstallDir -DisableFallback:$DisableToolchainFallback
if (-not $dumpbin) {
	throw @"
dumpbin.exe was not found (VCToolsInstallDir='$VcToolsInstallDir', env:VCToolsInstallDir='$($env:VCToolsInstallDir)').
BugSplatMonitor.exe is a vendor /MD PE; MSVC runtime DLLs must be copied next to Envy.exe when dumpbin reports dependents.
Build from a Visual Studio installation with the C++ x64/x86 tools workload, or run MSBuild from a Developer Command Prompt so VCToolsInstallDir is set.
"@
}

$needed = @(Get-BugSplatOutputRequiredDlls -MonitorPath $monitor -DumpBinPath $dumpbin -Configuration $Configuration -Platform $Platform)
if ($needed.Count -eq 0) {
	Write-Host "BugSplatMonitor.exe reports no extra MSVC CRT DLLs; nothing to copy."
	exit 0
}

$redistDir = Get-EnvyVcRedistDllDir -VcToolsInstallDir $VcToolsInstallDir
$debugRedistDir = Get-EnvyVcDebugRedistDllDir -VcToolsInstallDir $VcToolsInstallDir
$nonUcrtRelease = @($needed | Where-Object { $_ -inotmatch 'd\.dll$' -and $_ -inotmatch '^ucrtbase\.dll$' })
if (-not $redistDir -and $nonUcrtRelease.Count -gt 0) {
	throw "BugSplatMonitor.exe requires $($needed -join ', ') but MSVC vc_redist.x64 CRT folder was not found. Install VS C++ tools or copy redist DLLs manually."
}
if (-not $debugRedistDir -and ($needed | Where-Object { $_ -imatch 'd\.dll$' })) {
	$nonUcrtDebug = @($needed | Where-Object { $_ -imatch 'd\.dll$' -and $_ -inotmatch '^ucrtbased\.dll$' })
	if ($nonUcrtDebug.Count -gt 0) {
		throw "BugSplatMonitor.exe requires Debug CRT DLLs ($($nonUcrtDebug -join ', ')) but the MSVC debug_nonredist folder was not found. Install VS C++ tools with debug CRT support."
	}
}

foreach ($dll in $needed) {
	$src = if ($dll -imatch '^ucrtbase(?:d)?\.dll$') {
		Get-EnvyWindowsSdkUcrtDllPath -Name $dll
	} else {
		$sourceDir = if ($dll -imatch 'd\.dll$') { $debugRedistDir } else { $redistDir }
		Join-Path $sourceDir $dll
	}
	if (-not $src) {
		throw "Windows SDK UCRT DLL not found: $dll"
	}
	if (-not (Test-Path -LiteralPath $src)) {
		throw "Missing $src (required by BugSplatMonitor.exe)"
	}
	Copy-Item -Force $src (Join-Path $dest $dll)
}
Write-Host "Copied BugSplat VC runtime DLLs ($($needed -join ', ')) to $dest"
