#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
  Generate compile_commands.json for the Envy MSVC solution (IDE / SonarQube for VS Code).

.DESCRIPTION
  Uses Microsoft's msbuild-extractor-sample (design-time MSBuild evaluation; no full compile).
  Downloads a pinned self-contained win-x64 release into .local/msbuild-extractor/ on first run.

  Output defaults to the repository root (gitignored). Regenerate after toolset, SDK, or project changes.

.EXAMPLE
  .\scripts\generate-compile-commands.ps1
  .\scripts\generate-compile-commands.ps1 -Platform Win32 -Configuration Release
  .\scripts\generate-compile-commands.ps1 -Validate
#>
[CmdletBinding()]
param(
	[string]$Configuration = 'Release',
	[ValidateSet('x64', 'Win32')]
	[string]$Platform = 'x64',
	[string]$Output = '',
	[switch]$Validate,
	[switch]$SkipDownload,
	[string]$ExtractorPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExtractorVersion = 'v0.3.0'
$ExtractorSha256 = '543C5CC6B57A1B3EB46B11E56B8F35A9CA8676106426BDE6041CA2DC2E06F13C'
$ExtractorUrl = "https://github.com/microsoft/msbuild-extractor-sample/releases/download/$ExtractorVersion/msbuild-extractor-sample.exe"

function Get-RepoRoot {
	$git = Get-Command git -ErrorAction SilentlyContinue
	if ($git) {
		$fromGit = & git rev-parse --show-toplevel 2>$null
		if ($LASTEXITCODE -eq 0 -and $fromGit) {
			return $fromGit.Trim()
		}
	}
	return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Resolve-MsBuild {
	$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
	if (Test-Path -LiteralPath $vswhere) {
		# Prefer the newest installation that can load v145 projects (VS 2026 / 18.x), not an older side-by-side MSBuild.
		$found = & $vswhere -latest -prerelease -version '[18.0,19.0)' `
			-requires Microsoft.Component.MSBuild `
			-find 'MSBuild\**\Bin\amd64\MSBuild.exe' 2>$null | Select-Object -First 1
		if ($found) { return $found }
	}
	$candidates = @(
		'C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe',
		'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe',
		'C:\Program Files\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe',
		'C:\Program Files\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe'
	)
	foreach ($c in $candidates) {
		if (Test-Path -LiteralPath $c) { return $c }
	}
	throw 'MSBuild.exe not found. Install Visual Studio 2026 (v145) with the C++ workload.'
}

function Get-ExtractorExe {
	param(
		[string]$Root,
		[string]$Preferred,
		[bool]$NoDownload
	)
	if ($Preferred) {
		if (-not (Test-Path -LiteralPath $Preferred)) {
			throw "Extractor not found: $Preferred"
		}
		return (Resolve-Path -LiteralPath $Preferred).Path
	}

	$cacheDir = Join-Path $Root '.local\msbuild-extractor'
	$exeName = "msbuild-extractor-sample-$ExtractorVersion.exe"
	$cached = Join-Path $cacheDir $exeName
	if (Test-Path -LiteralPath $cached) {
		$cachedHash = (Get-FileHash -LiteralPath $cached -Algorithm SHA256).Hash
		if ($cachedHash -eq $ExtractorSha256) {
			return $cached
		}
		Write-Warning "Cached extractor SHA256 mismatch (got $cachedHash, expected $ExtractorSha256); removing and redownloading."
		Remove-Item -LiteralPath $cached -Force -ErrorAction Stop
		if ($NoDownload) {
			throw "Cached extractor at $cached failed SHA256 verification. Run without -SkipDownload or pass a verified -ExtractorPath."
		}
	}
	if ($NoDownload) {
		throw "Extractor not cached at $cached. Run without -SkipDownload or pass -ExtractorPath."
	}

	New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
	$tmp = Join-Path $cacheDir 'msbuild-extractor-sample.download'
	Write-Host "Downloading msbuild-extractor-sample $ExtractorVersion ..." -ForegroundColor Cyan
	Write-Host $ExtractorUrl -ForegroundColor DarkGray
	Invoke-WebRequest -Uri $ExtractorUrl -OutFile $tmp -UseBasicParsing

	$hash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash
	if ($hash -ne $ExtractorSha256) {
		Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
		throw "SHA256 mismatch for downloaded extractor (got $hash, expected $ExtractorSha256)."
	}

	Move-Item -LiteralPath $tmp -Destination $cached -Force
	return $cached
}

$root = Get-RepoRoot
Set-Location $root

if (-not $Output) {
	$Output = Join-Path $root 'compile_commands.json'
} elseif (-not [System.IO.Path]::IsPathRooted($Output)) {
	$Output = Join-Path $root $Output
}

$configPath = Join-Path $PSScriptRoot 'msbuild-extractor.envy.json'
if (-not (Test-Path -LiteralPath $configPath)) {
	throw "Missing config: $configPath"
}

$msbuild = Resolve-MsBuild
$extractor = Get-ExtractorExe -Root $root -Preferred $ExtractorPath -NoDownload:$SkipDownload

$extraProps = @()
if ($Platform -eq 'Win32') {
	$extraProps += @(
		'--msbuild-property', 'VcpkgEnableManifest=true',
		'--msbuild-property', 'VcpkgTriplet=x86-windows-static'
	)
}

$extractorArgs = @(
	'--config', $configPath,
	'-c', $Configuration,
	'-a', $Platform,
	'-o', $Output,
	'--msbuild-path', $msbuild
) + $extraProps

if ($Validate) {
	$extractorArgs += '--validate'
}

Write-Host "MSBuild:    $msbuild" -ForegroundColor DarkGray
Write-Host "Extractor:  $extractor" -ForegroundColor DarkGray
Write-Host "Output:     $Output" -ForegroundColor DarkGray
Write-Host "Config:     $Configuration | $Platform" -ForegroundColor DarkGray

& $extractor @extractorArgs
if ($LASTEXITCODE -ne 0) {
	throw "msbuild-extractor-sample failed (exit $LASTEXITCODE)."
}

if (-not (Test-Path -LiteralPath $Output)) {
	throw "Expected output was not created: $Output"
}

$entryCount = (Get-Content -LiteralPath $Output -Raw | ConvertFrom-Json).Count
Write-Host ""
Write-Host "Wrote $Output ($entryCount compile command entries)." -ForegroundColor Green
Write-Host 'Point SonarQube for VS Code / clangd at this file; regenerate after project or toolchain changes.' -ForegroundColor DarkGray
