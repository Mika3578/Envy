#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Import the official BugSplat Native Windows SDK into ThirdParty/BugSplat.

.DESCRIPTION
  Normalizes the SDK layout expected by Envy.CrashReporting.props.
  Verifies each file against ThirdParty/BugSplat/SDK-HASHES.json when entries exist.

  Download (BugSplat account): https://app.bugsplat.com/browse/download_item.php?item=native

.PARAMETER SourceRoot
  Unzipped SDK root (folder containing inc/ and x64/, or inner BugSplat/).

.PARAMETER DestRoot
  Defaults to <repo>/ThirdParty/BugSplat

.PARAMETER RecordReferenceHashes
  After copying, write SHA-256 reference hashes for the imported files.
  Use only after verifying the SDK came from the official BugSplat download.

.PARAMETER AllowUnlistedSource
  Import when SDK-HASHES.json has no entries (first-time maintainer import only).
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)][string]$SourceRoot,
	[string]$DestRoot = '',
	[switch]$RecordReferenceHashes,
	[switch]$AllowUnlistedSource
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

function Load-ReferenceHashes {
	param([string]$Path)
	if (-not (Test-Path -LiteralPath $Path)) {
		return @{}
	}
	$json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
	$map = @{}
	if ($json.files) {
		$json.files.PSObject.Properties | ForEach-Object { $map[$_.Name] = $_.Value.ToUpperInvariant() }
	}
	return $map
}

function Assert-SourceHash {
	param(
		[string]$SourceFile,
		[string]$RelativePath,
		[hashtable]$Reference,
		[bool]$AllowUnlisted
	)
	$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SourceFile).Hash.ToUpperInvariant()
	if ($Reference.ContainsKey($RelativePath)) {
		$expected = $Reference[$RelativePath]
		if ($hash -ne $expected) {
			throw "SHA-256 mismatch for $RelativePath. Expected $expected got $hash. Use a verified official SDK or -RecordReferenceHashes after deliberate upgrade."
		}
		Write-Host "Verified $RelativePath" -ForegroundColor DarkGray
	} elseif ($Reference.Count -gt 0) {
		throw "No reference hash for $RelativePath in SDK-HASHES.json. Re-run with -RecordReferenceHashes after SDK upgrade review."
	} elseif (-not $AllowUnlisted) {
		throw "SDK-HASHES.json has no entries. First import requires -AllowUnlistedSource (official download only) then commit SDK-HASHES.json from -RecordReferenceHashes."
	}
	return $hash
}

$repo = Get-RepoRoot
if (-not $DestRoot) { $DestRoot = Join-Path $repo 'ThirdParty\BugSplat' }
$sdk = Resolve-SdkRoot -Root $SourceRoot
$referencePath = Join-Path $DestRoot 'SDK-HASHES.json'
$reference = Load-ReferenceHashes -Path $referencePath

New-Item -ItemType Directory -Force -Path $DestRoot | Out-Null

$incDest = Join-Path $DestRoot 'inc'
if (Test-Path $incDest) { Remove-Item -Recurse -Force $incDest }
$incSrc = Join-Path $sdk 'inc\BugSplat.h'
Assert-SourceHash -SourceFile $incSrc -RelativePath 'inc/BugSplat.h' -Reference $reference -AllowUnlisted:$AllowUnlistedSource.IsPresent
Copy-Item -Recurse -Force (Join-Path $sdk 'inc') $incDest

$manifest = @()
$newReference = [ordered]@{ description = 'Expected SHA-256 of official BugSplat native SDK files before import.'; files = [ordered]@{} }

foreach ($config in @('Release', 'Debug')) {
	$libSrc = Find-LibMt -SdkRoot $sdk -Config $config
	if (-not $libSrc) { throw "Missing official lib/mt for $config under $sdk" }
	$relLib = "x64/$config/lib/mt/BugSplat.lib"
	$libHash = Assert-SourceHash -SourceFile $libSrc -RelativePath $relLib -Reference $reference -AllowUnlisted:$AllowUnlistedSource.IsPresent
	$libDestDir = Join-Path $DestRoot "x64\$config\lib\mt"
	New-Item -ItemType Directory -Force -Path $libDestDir | Out-Null
	Copy-Item -Force $libSrc (Join-Path $libDestDir 'BugSplat.lib')
	$manifest += [pscustomobject]@{ Path = $relLib; Sha256 = $libHash }
	$newReference.files[$relLib] = $libHash

	$binSrc = Find-BinDir -SdkRoot $sdk -Config $config
	if (-not $binSrc) { throw "Missing BugSplatMonitor.exe for $config under $sdk" }
	$binDest = Join-Path $DestRoot "x64\$config\bin"
	New-Item -ItemType Directory -Force -Path $binDest | Out-Null
	foreach ($name in @('BugSplatMonitor.exe', 'BugSplatWer.dll', 'BugSplatRc.dll')) {
		$srcFile = Join-Path $binSrc $name
		if (Test-Path -LiteralPath $srcFile) {
			$relBin = "x64/$config/bin/$name"
			$binHash = Assert-SourceHash -SourceFile $srcFile -RelativePath $relBin -Reference $reference -AllowUnlisted:$AllowUnlistedSource.IsPresent
			Copy-Item -Force $srcFile (Join-Path $binDest $name)
			$manifest += [pscustomobject]@{ Path = $relBin; Sha256 = $binHash }
			$newReference.files[$relBin] = $binHash
		}
	}
}

$manifestPath = Join-Path $DestRoot 'SDK-MANIFEST.json'
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

if ($RecordReferenceHashes) {
	$newReference | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $referencePath -Encoding UTF8
	Write-Host "Updated reference hashes: $referencePath" -ForegroundColor Green
}

Write-Host "Imported BugSplat SDK from $sdk to $DestRoot"
Write-Host "Wrote $manifestPath"
