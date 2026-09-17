#Requires -Version 7.0
<#
.SYNOPSIS
  Verify release tag metadata against version.json / Envy.rc / optional Envy.exe.

.DESCRIPTION
  Fails with a non-zero exit code when the tag does not match the product
  version sources. Does not touch vcpkg.json (distinct version-string semantics).
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$Tag,

	[Parameter(Mandatory = $false)]
	[string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,

	[Parameter(Mandatory = $false)]
	[string]$EnvyExePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Fail([string]$Message)
{
	Write-Error $Message
	exit 1
}

function Get-NormalizedTag([string]$Value)
{
	$t = $Value.Trim()
	if ($t.StartsWith('refs/tags/'))
	{
		$t = $t.Substring('refs/tags/'.Length)
	}
	if (-not $t.StartsWith('v'))
	{
		Write-Fail "Tag must start with 'v' (got '$Value')."
	}
	return $t
}

$tagName = Get-NormalizedTag $Tag
$versionFromTag = $tagName.Substring(1)

$versionJsonPath = Join-Path $RepoRoot 'version.json'
$envyRcPath = Join-Path $RepoRoot 'Envy\Envy.rc'

if (-not (Test-Path -LiteralPath $versionJsonPath))
{
	Write-Fail "Missing version.json at $versionJsonPath"
}
if (-not (Test-Path -LiteralPath $envyRcPath))
{
	Write-Fail "Missing Envy.rc at $envyRcPath"
}

$vj = Get-Content -LiteralPath $versionJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $vj.fullVersion)
{
	Write-Fail 'version.json is missing fullVersion.'
}
if ($vj.fullVersion -ne $versionFromTag)
{
	Write-Fail "version.json fullVersion '$($vj.fullVersion)' does not match tag version '$versionFromTag'."
}
if ($vj.git -and $vj.git.intendedTag -and ($vj.git.intendedTag -ne $tagName))
{
	Write-Fail "version.json git.intendedTag '$($vj.git.intendedTag)' does not match tag '$tagName'."
}

$expectedFileVersion = '{0}.{1}.{2}.{3}' -f $vj.major, $vj.minor, $vj.patch, $vj.build
$expectedCsv = '{0},{1},{2},{3}' -f $vj.major, $vj.minor, $vj.patch, $vj.build

$rc = Get-Content -LiteralPath $envyRcPath -Raw
if ($rc -notmatch ("FILEVERSION\s+" + [regex]::Escape($expectedCsv)))
{
	Write-Fail "Envy.rc FILEVERSION does not match expected $expectedCsv."
}
if ($rc -notmatch ("PRODUCTVERSION\s+" + [regex]::Escape($expectedCsv)))
{
	Write-Fail "Envy.rc PRODUCTVERSION does not match expected $expectedCsv."
}
if ($vj.displayVersion)
{
	$escapedDisplay = [regex]::Escape($vj.displayVersion)
	if ($rc -notmatch ('VALUE\s+"ProductVersion",\s+"' + $escapedDisplay + '"'))
	{
		Write-Fail "Envy.rc ProductVersion string does not match version.json displayVersion '$($vj.displayVersion)'."
	}
}
$escapedFile = [regex]::Escape($expectedFileVersion)
if ($rc -notmatch ('VALUE\s+"FileVersion",\s+"' + $escapedFile + '"'))
{
	Write-Fail "Envy.rc FileVersion string does not match expected '$expectedFileVersion'."
}

Write-Host "OK: tag $tagName matches version.json ($($vj.fullVersion)) and Envy.rc ($expectedFileVersion)."

if ($EnvyExePath)
{
	if (-not (Test-Path -LiteralPath $EnvyExePath))
	{
		Write-Fail "Envy.exe not found at $EnvyExePath"
	}
	$info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path -LiteralPath $EnvyExePath).Path)
	$fileVer = $info.FileVersion
	if (-not $fileVer)
	{
		Write-Fail "Could not read FileVersion from $EnvyExePath"
	}
	# FileVersion may be "4.2.0.1" or padded; compare numeric parts.
	$norm = ($fileVer -split '[^\d]+' | Where-Object { $_ -ne '' }) -join '.'
	$expectedNorm = ($expectedFileVersion -split '[^\d]+' | Where-Object { $_ -ne '' }) -join '.'
	if ($norm -ne $expectedNorm -and -not $fileVer.StartsWith($expectedFileVersion))
	{
		Write-Fail "Envy.exe FileVersion '$fileVer' does not match expected '$expectedFileVersion'."
	}
	Write-Host "OK: Envy.exe FileVersion=$fileVer"
}

Write-Host 'verify-version: PASS'
exit 0
