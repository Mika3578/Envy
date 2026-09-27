#!/usr/bin/env pwsh
# Fail-closed verification of the committed ThirdParty/BugSplat tree against SDK-HASHES.json.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot (Join-Path 'lib' 'BugSplatSdkTrust.psm1')
Import-Module $modulePath -Force

$repo = git -C $PSScriptRoot rev-parse --show-toplevel 2>$null
if ($LASTEXITCODE -ne 0 -or -not $repo) {
	$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
$destRoot = Join-Path $repo 'ThirdParty\BugSplat'
$referencePath = Join-Path $destRoot 'SDK-HASHES.json'

$null = Test-BugSplatCommittedSdkTree -DestRoot $destRoot -ReferenceHashesPath $referencePath
Write-Host "verify-bugsplat-sdk-committed.ps1: OK ($destRoot matches SDK-HASHES.json)"
