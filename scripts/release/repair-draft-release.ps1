#Requires -Version 7.0
<#
.SYNOPSIS
  Repair an existing draft release by uploading assets from a local directory
  or a prior Actions artifact run — without retagging or publishing.

.EXAMPLE
  pwsh ./scripts/release/repair-draft-release.ps1 `
    -Tag v4.2.0-preview.1 `
    -ReleaseId 391048728 `
    -AssetDir ./release

.EXAMPLE
  pwsh ./scripts/release/repair-draft-release.ps1 `
    -Tag v4.2.0-preview.1 `
    -ReleaseId 391048728 `
    -ArtifactRunId 35271515256 `
    -ArtifactName release-v4.2.0-preview.1
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$Tag,

	[Parameter(Mandatory = $true)]
	[string]$ReleaseId,

	[Parameter(Mandatory = $false)]
	[string]$AssetDir = '',

	[Parameter(Mandatory = $false)]
	[string]$ArtifactRunId = '',

	[Parameter(Mandatory = $false)]
	[string]$ArtifactName = '',

	[Parameter(Mandatory = $false)]
	[string]$Repository = $(if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { 'Mika3578/Envy' }),

	[Parameter(Mandatory = $false)]
	[bool]$Prerelease = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Fail([string]$Message)
{
	Write-Error $Message
	exit 1
}

if (-not $AssetDir -and -not $ArtifactRunId)
{
	Write-Fail 'Provide -AssetDir and/or -ArtifactRunId.'
}

$work = $AssetDir
$tempRoot = $null
try
{
	if ($ArtifactRunId)
	{
		if (-not $ArtifactName)
		{
			$ArtifactName = "release-$Tag"
		}
		$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("envy-repair-" + [guid]::NewGuid().ToString('N'))
		New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
		Write-Host "Downloading artifact '$ArtifactName' from run $ArtifactRunId..."
		& gh run download $ArtifactRunId --repo $Repository --name $ArtifactName --dir $tempRoot
		if ($LASTEXITCODE -ne 0)
		{
			Write-Fail "gh run download failed for run $ArtifactRunId / artifact $ArtifactName"
		}
		# Artifact may extract flat or into a subfolder.
		$candidate = Join-Path $tempRoot $ArtifactName
		if (Test-Path -LiteralPath $candidate)
		{
			$work = $candidate
		}
		else
		{
			$work = $tempRoot
		}
	}

	$verify = Join-Path $PSScriptRoot 'verify-artifacts.ps1'
	$publish = Join-Path $PSScriptRoot 'publish-draft-release.ps1'
	$version = $Tag.Trim()
	if ($version.StartsWith('v')) { $version = $version.Substring(1) }

	& $verify -ReleaseDir $work -Version $version
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

	& $publish -Tag $Tag -AssetDir $work -ReleaseId $ReleaseId -Repository $Repository -Prerelease:$Prerelease
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

	Write-Host 'repair-draft-release: PASS'
	exit 0
}
finally
{
	if ($tempRoot)
	{
		Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
	}
}
