#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Import the official BugSplat Native Windows SDK into ThirdParty/BugSplat.

.DESCRIPTION
  Normalizes the SDK layout expected by Envy.CrashReporting.props:
    ThirdParty/BugSplat/inc/BugSplat.h
    ThirdParty/BugSplat/x64/Release/lib/mt/BugSplat.lib
    ThirdParty/BugSplat/x64/Debug/lib/mt/BugSplat.lib
    ThirdParty/BugSplat/x64/<Config>/bin/BugSplatMonitor.exe (+ Wer/Rc)

  Download (BugSplat account): https://app.bugsplat.com/browse/download_item.php?item=native

.PARAMETER SourceRoot
  Unzipped SDK root (folder containing inc/ and x64/, or inner BugSplat/).

.PARAMETER DestRoot
  Defaults to <repo>/ThirdParty/BugSplat
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)][string]$SourceRoot,
	[string]$DestRoot = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-RepoRoot {
	$fromGit = git rev-parse --show-toplevel 2>$null
	if ($LASTEXITCODE -eq 0 -and $fromGit) { return $fromGit.Trim() }
	return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Resolve-SdkRoot {
	param([string]$Root)
	$Root = (Resolve-Path -LiteralPath $Root).Path
	if (Test-Path -LiteralPath (Join-Path $Root 'inc\BugSplat.h')) { return $Root }
	$inner = Join-Path $Root 'BugSplat'
	if (Test-Path -LiteralPath (Join-Path $inner 'inc\BugSplat.h')) { return $inner }
	throw "Could not find inc\BugSplat.h under $Root or $inner"
}

function Find-LibMt {
	param([string]$SdkRoot, [string]$Config)
	$candidates = @(
		(Join-Path $SdkRoot "x64\$Config\lib\mt\BugSplat.lib"),
		(Join-Path $SdkRoot "$Config\x64\lib\mt\BugSplat.lib")
	)
	foreach ($c in $candidates) {
		if (Test-Path -LiteralPath $c) { return $c }
	}
	return $null
}

function Find-BinDir {
	param([string]$SdkRoot, [string]$Config)
	$candidates = @(
		(Join-Path $SdkRoot "x64\$Config\bin"),
		(Join-Path $SdkRoot "x64\$Config"),
		(Join-Path $SdkRoot "$Config\x64\bin")
	)
	foreach ($c in $candidates) {
		if (Test-Path -LiteralPath (Join-Path $c 'BugSplatMonitor.exe')) { return $c }
	}
	return $null
}

$repo = Get-RepoRoot
if (-not $DestRoot) { $DestRoot = Join-Path $repo 'ThirdParty\BugSplat' }
$sdk = Resolve-SdkRoot -Root $SourceRoot
New-Item -ItemType Directory -Force -Path $DestRoot | Out-Null

$incDest = Join-Path $DestRoot 'inc'
if (Test-Path $incDest) { Remove-Item -Recurse -Force $incDest }
Copy-Item -Recurse -Force (Join-Path $sdk 'inc') $incDest

$manifest = @()
foreach ($config in @('Release', 'Debug')) {
	$libSrc = Find-LibMt -SdkRoot $sdk -Config $config
	if (-not $libSrc) { throw "Missing official lib/mt for $config under $sdk" }
	$libDestDir = Join-Path $DestRoot "x64\$config\lib\mt"
	New-Item -ItemType Directory -Force -Path $libDestDir | Out-Null
	Copy-Item -Force $libSrc (Join-Path $libDestDir 'BugSplat.lib')
	$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $libSrc).Hash
	$manifest += [pscustomobject]@{ Path = "x64/$config/lib/mt/BugSplat.lib"; Sha256 = $hash }

	$binSrc = Find-BinDir -SdkRoot $sdk -Config $config
	if (-not $binSrc) { throw "Missing BugSplatMonitor.exe for $config under $sdk" }
	$binDest = Join-Path $DestRoot "x64\$config\bin"
	New-Item -ItemType Directory -Force -Path $binDest | Out-Null
	foreach ($name in @('BugSplatMonitor.exe', 'BugSplatWer.dll', 'BugSplatRc.dll')) {
		$srcFile = Join-Path $binSrc $name
		if (Test-Path -LiteralPath $srcFile) {
			Copy-Item -Force $srcFile (Join-Path $binDest $name)
			$manifest += [pscustomobject]@{ Path = "x64/$config/bin/$name"; Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $srcFile).Hash }
		}
	}
}

$manifestPath = Join-Path $DestRoot 'SDK-MANIFEST.json'
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "Imported BugSplat SDK from $sdk to $DestRoot"
Write-Host "Wrote $manifestPath"
