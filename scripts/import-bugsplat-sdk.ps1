#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Import the official BugSplat Native Windows SDK into ThirdParty/BugSplat.

.DESCRIPTION
  Fail-closed import: every file is hashed from the maintainer-supplied source tree
  and compared to SHA-256 values already committed in ThirdParty/BugSplat/SDK-HASHES.json
  before any copy runs.

  This script never writes or updates SDK-HASHES.json. Establishing the baseline is a
  separate maintainer operation (scripts/establish-bugsplat-sdk-trust.ps1).

  Download (BugSplat account): https://app.bugsplat.com/browse/download_item.php?item=native
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)][string]$SourceRoot,
	[string]$DestRoot = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-RepoRoot {
	$scriptDir = $PSScriptRoot
	if (-not $scriptDir) {
		$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
	}
	$fromGit = git -C $scriptDir rev-parse --show-toplevel 2>$null
	if ($LASTEXITCODE -eq 0 -and $fromGit) { return $fromGit.Trim() }
	return (Resolve-Path (Join-Path $scriptDir '..')).Path
}

$repo = Get-RepoRoot
if (-not $DestRoot) { $DestRoot = Join-Path $repo 'ThirdParty\BugSplat' }
$referencePath = Join-Path $DestRoot 'SDK-HASHES.json'

Import-Module (Join-Path $PSScriptRoot (Join-Path 'lib' 'BugSplatSdkTrust.psm1')) -Force

$result = Invoke-BugSplatSdkImport -SourceRoot $SourceRoot -DestRoot $DestRoot -ReferenceHashesPath $referencePath
Write-Host "Imported BugSplat SDK from $($result.SdkRoot) to $($result.DestRoot)"
Write-Host "Wrote $($result.ManifestPath)"
