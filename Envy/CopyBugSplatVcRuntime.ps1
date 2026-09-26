#!/usr/bin/env pwsh
# Copy MSVC/UCRT DLLs required by BugSplat /MD PEs next to Envy.exe (x64 only).
param(
	[string]$Configuration,
	[string]$Platform
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Platform -ne 'x64') { exit 0 }
if (-not $Configuration) { throw 'Configuration required' }

$dest = Join-Path $PSScriptRoot "$Configuration $Platform"
if (-not (Test-Path -LiteralPath $dest)) { exit 0 }

$monitor = Join-Path $dest 'BugSplatMonitor.exe'
if (-not (Test-Path -LiteralPath $monitor)) { exit 0 }

function Find-DumpBin {
	$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
	if (-not (Test-Path -LiteralPath $vswhere)) { return $null }
	$install = (& $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -as [string]
	if (-not $install) { return $null }
	$dumpbin = Get-ChildItem -Path (Join-Path $install 'VC\Tools\MSVC') -Recurse -Filter 'dumpbin.exe' -ErrorAction SilentlyContinue |
		Where-Object { $_.FullName -match '\\Hostx64\\x64\\dumpbin\.exe$' } |
		Select-Object -First 1
	if ($dumpbin) { return $dumpbin.FullName }
	return $null
}

function Find-VcRedistDllDir {
	$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
	if (-not (Test-Path -LiteralPath $vswhere)) { return $null }
	$install = (& $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -as [string]
	if (-not $install) { return $null }

	# Prefer official vc_redist CRT folders (shipping redist), not IDE toolchains.
	$msvcRoot = Join-Path $install 'VC\Redist\MSVC'
	if (Test-Path -LiteralPath $msvcRoot) {
		foreach ($ver in Get-ChildItem -LiteralPath $msvcRoot -Directory | Sort-Object Name -Descending) {
			$candidates = @(
				(Join-Path $ver.FullName 'vc_redist.x64\Microsoft.VC143.CRT'),
				(Join-Path $ver.FullName 'vc_redist.x64\Microsoft.VC142.CRT'),
				(Join-Path $ver.FullName 'x64\Microsoft.VC143.CRT'),
				(Join-Path $ver.FullName 'Microsoft.VC143.CRT')
			)
			foreach ($c in $candidates) {
				if (Test-Path -LiteralPath (Join-Path $c 'vcruntime140.dll')) { return $c }
			}
		}
		$hit = Get-ChildItem -LiteralPath $msvcRoot -Recurse -Filter 'vcruntime140.dll' -File -ErrorAction SilentlyContinue |
			Where-Object { $_.FullName -match '\\x64\\' -or $_.FullName -match 'vc_redist\.x64' } |
			Sort-Object FullName -Descending |
			Select-Object -First 1
		if ($hit) { return $hit.DirectoryName }
	}

	$toolsRoot = Join-Path $install 'VC\Tools\MSVC'
	if (Test-Path -LiteralPath $toolsRoot) {
		foreach ($ver in Get-ChildItem -LiteralPath $toolsRoot -Directory | Sort-Object Name -Descending) {
			$hostBin = Join-Path $ver.FullName 'bin\Hostx64\x64'
			if (Test-Path -LiteralPath (Join-Path $hostBin 'vcruntime140.dll')) {
				return $hostBin
			}
		}
	}
	return $null
}

$dumpbin = Find-DumpBin
if (-not $dumpbin) {
	Write-Warning "dumpbin not found; skipping BugSplat VC runtime copy for $monitor"
	exit 0
}

$depOut = & $dumpbin /nologo /dependents $monitor 2>&1 | Out-String
$needed = @()
foreach ($name in @('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll', 'msvcp140_1.dll', 'msvcp140_2.dll')) {
	if ($depOut -match "(?im)^\s+$name\s*$") { $needed += $name }
}
if ($needed.Count -eq 0) {
	Write-Host "BugSplatMonitor.exe reports no extra MSVC CRT DLLs; nothing to copy."
	exit 0
}

$redistDir = Find-VcRedistDllDir
if (-not $redistDir) {
	throw "BugSplatMonitor.exe requires $($needed -join ', ') but MSVC vc_redist.x64 CRT folder was not found. Install VS C++ tools or copy redist DLLs manually."
}

foreach ($dll in $needed) {
	$src = Join-Path $redistDir $dll
	if (-not (Test-Path -LiteralPath $src)) {
		throw "Missing $src (required by BugSplatMonitor.exe)"
	}
	Copy-Item -Force $src (Join-Path $dest $dll)
}
Write-Host "Copied BugSplat VC runtime DLLs ($($needed -join ', ')) to $dest"
