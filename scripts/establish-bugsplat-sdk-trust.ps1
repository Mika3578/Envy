#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Establish or upgrade the maintainer-reviewed SHA-256 baseline for the BugSplat Native SDK.

.DESCRIPTION
  BugSplat does not publish an independent SHA-256 manifest for the login-gated Native C++ zip.
  This script is the ONLY supported way to write ThirdParty/BugSplat/SDK-HASHES.json.

  It computes hashes from files you supply, validates Authenticode on PE binaries when present,
  and documents the trust limitation explicitly. It does NOT prove the first portal download
  was uncompromised — that requires maintainer review of the download channel plus PR review
  of the committed baseline.

  Normal CI and day-to-day imports must use scripts/import-bugsplat-sdk.ps1, which refuses to
  run without a populated SDK-HASHES.json and never rewrites it.

.PARAMETER WriteReferenceHashes
  Write SDK-HASHES.json under DestRoot. Requires explicit maintainer confirmation switches.

.PARAMETER AlsoImport
  After writing hashes, run import-bugsplat-sdk.ps1 (same source tree).
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)][string]$SourceRoot,
	[string]$DestRoot = '',
	[Parameter(Mandatory = $true)][string]$SdkVersion,
	[switch]$WriteReferenceHashes,
	[switch]$AlsoImport,
	[switch]$ConfirmOfficialPortalDownload,
	[switch]$ConfirmMaintainerBaselineReview,
	[switch]$AllowBaselineUpgrade
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $WriteReferenceHashes -and -not $AlsoImport) {
	throw 'Specify -WriteReferenceHashes (and confirmation switches) to record a baseline, or -AlsoImport with an existing SDK-HASHES.json.'
}

if ($WriteReferenceHashes) {
	if (-not $ConfirmOfficialPortalDownload) {
		throw '-ConfirmOfficialPortalDownload is required. Download only from https://app.bugsplat.com/browse/download_item.php?item=native while signed in to BugSplat.'
	}
	if (-not $ConfirmMaintainerBaselineReview) {
		throw '-ConfirmMaintainerBaselineReview is required. SHA-256 here is maintainer-reviewed TOFU, not an independent publisher manifest.'
	}
}

function Get-RepoRoot {
	$fromGit = git rev-parse --show-toplevel 2>$null
	if ($LASTEXITCODE -eq 0 -and $fromGit) { return $fromGit.Trim() }
	return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

$repo = Get-RepoRoot
if (-not $DestRoot) { $DestRoot = Join-Path $repo 'ThirdParty\BugSplat' }
Import-Module (Join-Path $PSScriptRoot (Join-Path 'lib' 'BugSplatSdkTrust.psm1')) -Force

$proposal = Invoke-BugSplatSdkTrustProposal -SourceRoot $SourceRoot
$doc = New-BugSplatTrustDocumentSkeleton -SdkVersion $SdkVersion
foreach ($entry in $proposal.FileHashes.GetEnumerator()) {
	$doc.files[$entry.Key] = $entry.Value
}

if ($WriteReferenceHashes) {
	$referencePath = Join-Path $DestRoot 'SDK-HASHES.json'
	if (Test-Path -LiteralPath $referencePath) {
		$existing = Read-BugSplatReferenceHashes -Path $referencePath
		if ($existing.Map.Count -gt 0 -and -not $AllowBaselineUpgrade) {
			throw "Refusing to overwrite non-empty $referencePath. Use -AllowBaselineUpgrade after a deliberate SDK version bump review."
		}
	}
	New-Item -ItemType Directory -Force -Path $DestRoot | Out-Null
	$doc | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $referencePath -Encoding UTF8
	Write-Host "Wrote maintainer baseline: $referencePath" -ForegroundColor Green
}

if ($AlsoImport) {
	& (Join-Path $PSScriptRoot 'import-bugsplat-sdk.ps1') -SourceRoot $SourceRoot -DestRoot $DestRoot
}
