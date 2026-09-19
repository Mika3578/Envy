#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Restore the root vcpkg.json manifest into vcpkg_installed\<triplet>.

.DESCRIPTION
  GitHub Actions runs `vcpkg install --triplet=<triplet>` before MSBuild
  (see `.github/actions/windows-msbuild/action.yml`). Visual Studio does not.

  Envy.vcxproj sets VcpkgEnabled / VcpkgEnableManifest / VcpkgManifestRoot /
  VcpkgTriplet, but it does not import vcpkg.targets. Those properties do not
  restore packages by themselves. Even with `vcpkg integrate install`, vcpkg
  MSBuild restore runs before ClCompile/Midl — after PreBuildEvent, which
  copies crashpad_handler.exe from vcpkg_installed.

  This script is the local equivalent of the CI restore step. It does not clone vcpkg unless -CloneVcpkg is passed.

.EXAMPLE
  .\scripts\bootstrap-vcpkg.ps1
  .\scripts\bootstrap-vcpkg.ps1 -Triplet x86-windows-static
  .\scripts\bootstrap-vcpkg.ps1 -All
  .\scripts\bootstrap-vcpkg.ps1 -CheckOnly
#>
[CmdletBinding()]
param(
	[string]$Triplet = 'x64-windows-static',
	[switch]$All,
	[switch]$CheckOnly,
	[switch]$CloneVcpkg
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-RepoRoot {
	$fromGit = git rev-parse --show-toplevel 2>$null
	if ($LASTEXITCODE -eq 0 -and $fromGit) {
		return $fromGit.Trim()
	}
	return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Resolve-VcpkgExe {
	param(
		[Parameter(Mandatory = $true)][string]$Root,
		[switch]$AllowClone
	)

	$candidates = @()
	if ($env:VCPKG_ROOT) {
		$candidates += (Join-Path $env:VCPKG_ROOT 'vcpkg.exe')
		$candidates += (Join-Path $env:VCPKG_ROOT 'vcpkg')
	}
	if ($env:VCPKG_INSTALLATION_ROOT) {
		$candidates += (Join-Path $env:VCPKG_INSTALLATION_ROOT 'vcpkg.exe')
		$candidates += (Join-Path $env:VCPKG_INSTALLATION_ROOT 'vcpkg')
	}
	$candidates += (Join-Path $Root 'vcpkg\vcpkg.exe')
	$candidates += (Join-Path $Root 'vcpkg\vcpkg')
	$cmd = Get-Command vcpkg -ErrorAction SilentlyContinue
	if ($cmd) {
		$candidates += $cmd.Source
	}

	foreach ($c in $candidates) {
		if ($c -and (Test-Path -LiteralPath $c)) {
			return $c
		}
	}

	if (-not $AllowClone) {
		throw @"
vcpkg.exe was not found.

Set VCPKG_ROOT (or VCPKG_INSTALLATION_ROOT) to a bootstrapped vcpkg tree,
put vcpkg on PATH, or clone it next to the repo and re-run with -CloneVcpkg:

  git clone https://github.com/microsoft/vcpkg.git
  .\vcpkg\bootstrap-vcpkg.bat -disableMetrics
  .\scripts\bootstrap-vcpkg.ps1 -Triplet $Triplet

Do not expect Visual Studio to download Crashpad/vcpkg during PreBuild.
"@
	}

	$vcpkgDir = Join-Path $Root 'vcpkg'
	if (-not (Test-Path -LiteralPath $vcpkgDir)) {
		Write-Host "Cloning vcpkg into $vcpkgDir (-CloneVcpkg was set)..." -ForegroundColor DarkCyan
		git clone https://github.com/microsoft/vcpkg.git $vcpkgDir
		if ($LASTEXITCODE -ne 0) {
			throw 'git clone of microsoft/vcpkg failed.'
		}
	}

	$bootstrapBat = Join-Path $vcpkgDir 'bootstrap-vcpkg.bat'
	$bootstrapSh = Join-Path $vcpkgDir 'bootstrap-vcpkg.sh'
	$exe = Join-Path $vcpkgDir 'vcpkg.exe'
	$unix = Join-Path $vcpkgDir 'vcpkg'
	$onWindows = $env:OS -eq 'Windows_NT'
	if (-not (Test-Path -LiteralPath $exe) -and -not (Test-Path -LiteralPath $unix)) {
		if ($onWindows -and (Test-Path -LiteralPath $bootstrapBat)) {
			Write-Host 'Bootstrapping vcpkg.exe...' -ForegroundColor DarkCyan
			& $bootstrapBat -disableMetrics
		} elseif (Test-Path -LiteralPath $bootstrapSh) {
			Write-Host 'Bootstrapping vcpkg...' -ForegroundColor DarkCyan
			& $bootstrapSh -disableMetrics
		} else {
			throw "vcpkg bootstrap script was not found under $vcpkgDir"
		}
	}

	if (Test-Path -LiteralPath $exe) { return $exe }
	if (Test-Path -LiteralPath $unix) { return $unix }
	throw "vcpkg was cloned but the executable is still missing under $vcpkgDir"
}

function Get-HandlerCandidates {
	param(
		[Parameter(Mandatory = $true)][string]$Installed
	)
	return @(
		(Join-Path $Installed 'tools\crashpad_handler.exe'),
		(Join-Path $Installed 'tools\crashpad\crashpad_handler.exe'),
		(Join-Path $Installed 'debug\tools\crashpad_handler.exe'),
		(Join-Path $Installed 'debug\tools\crashpad\crashpad_handler.exe')
	)
}

function Test-VcpkgInstalled {
	param(
		[Parameter(Mandatory = $true)][string]$Root,
		[Parameter(Mandatory = $true)][string]$TargetTriplet
	)
	$installed = Join-Path $Root "vcpkg_installed\$TargetTriplet"
	$result = [ordered]@{
		Triplet   = $TargetTriplet
		Installed = $installed
		Exists    = Test-Path -LiteralPath $installed
		Handler   = $null
	}
	if ($result.Exists) {
		foreach ($cand in (Get-HandlerCandidates -Installed $installed)) {
			if (Test-Path -LiteralPath $cand) {
				$result.Handler = $cand
				break
			}
		}
	}
	return $result
}

$root = Get-RepoRoot
Set-Location $root

if (-not (Test-Path -LiteralPath (Join-Path $root 'vcpkg.json'))) {
	throw "vcpkg.json was not found at the repository root: $root"
}

$triplets = @()
if ($All) {
	$triplets = @('x64-windows-static', 'x86-windows-static')
} else {
	$triplets = @($Triplet)
}

Write-Host "Repository : $root" -ForegroundColor DarkGray
Write-Host "Triplets   : $($triplets -join ', ')" -ForegroundColor DarkGray

$missing = @()
foreach ($t in $triplets) {
	$state = Test-VcpkgInstalled -Root $root -TargetTriplet $t
	if ($state.Exists) {
		Write-Host "OK  $($state.Installed)" -ForegroundColor Green
		if ($state.Handler) {
			Write-Host "    crashpad_handler: $($state.Handler)" -ForegroundColor DarkGray
		} else {
			Write-Host "    crashpad_handler.exe not found yet (vcpkg install still required if Crashpad is missing)." -ForegroundColor DarkYellow
			$missing += $t
		}
	} else {
		Write-Host "MISS $($state.Installed)" -ForegroundColor Yellow
		$missing += $t
	}
}

if ($CheckOnly) {
	if ($missing.Count -gt 0) {
		Write-Error @"
vcpkg_installed is incomplete for: $($missing -join ', ').

From the repository root run:
  .\scripts\bootstrap-vcpkg.ps1 -Triplet $($missing[0])

CI restore (not done by Visual Studio PreBuildEvent):
  vcpkg install --triplet=<triplet>
"@
		exit 1
	}
	Write-Host 'vcpkg_installed check OK' -ForegroundColor Green
	exit 0
}

$vcpkg = Resolve-VcpkgExe -Root $root -AllowClone:$CloneVcpkg
Write-Host "vcpkg      : $vcpkg" -ForegroundColor DarkGray

foreach ($t in $triplets) {
	Write-Host "== vcpkg install --triplet=$t ==" -ForegroundColor Cyan
	& $vcpkg install "--triplet=$t"
	if ($LASTEXITCODE -ne 0) {
		throw "vcpkg install --triplet=$t failed with exit $LASTEXITCODE"
	}
	$state = Test-VcpkgInstalled -Root $root -TargetTriplet $t
	if (-not $state.Exists) {
		throw "vcpkg install finished but $($state.Installed) is still missing."
	}
	if (-not $state.Handler) {
		throw "vcpkg install finished but crashpad_handler.exe was not found under $($state.Installed). Crashpad is a required root-manifest dependency."
	}
	Write-Host "Installed Crashpad handler: $($state.Handler)" -ForegroundColor Green
}

Write-Host 'vcpkg bootstrap OK. You can now build Visual Studio\Envy.sln (Debug/Release, x64/Win32).' -ForegroundColor Green
exit 0
