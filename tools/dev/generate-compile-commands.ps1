#Requires -Version 5.1
<#
.SYNOPSIS
	Build compile_commands.json at the repository root from MSVC CL.command.*.tlog files.

.DESCRIPTION
	Machine-local output (gitignored). Run after a Visual Studio / MSBuild build
	of Envy, HashLib, and TorrentEnvy for the chosen configuration.

.PARAMETER Configuration
	MSBuild-style pair, e.g. Release|x64 (default) or Debug|x64.
#>
param(
	[string]$Configuration = 'Release|x64'
)

$ErrorActionPreference = 'Stop'

function Get-RepoRoot
{
	$here = $PSScriptRoot
	while ($here)
	{
		if (Test-Path -LiteralPath (Join-Path $here 'Visual Studio\Envy.sln'))
		{
			return (Resolve-Path -LiteralPath $here).Path
		}
		$parent = Split-Path -Parent $here
		if (-not $parent -or $parent -eq $here) { break }
		$here = $parent
	}
	throw 'Could not locate repository root (Visual Studio\Envy.sln).'
}

function Find-MsvcClExe
{
	$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
	if (-not (Test-Path -LiteralPath $vswhere))
	{
		throw "vswhere.exe not found at: $vswhere. Install Visual Studio 2026 with the C++ workload."
	}

	$installPath = & $vswhere -latest -prerelease -products * `
		-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
		-property installationPath 2>$null | Select-Object -First 1
	if ([string]::IsNullOrWhiteSpace($installPath))
	{
		throw 'No Visual Studio installation with VC++ tools found (vswhere).'
	}

	$msvcRoot = Join-Path $installPath 'VC\Tools\MSVC'
	if (-not (Test-Path -LiteralPath $msvcRoot))
	{
		throw "MSVC toolset directory missing under: $msvcRoot"
	}

	$versionDir = Get-ChildItem -LiteralPath $msvcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
	if (-not $versionDir)
	{
		throw "No MSVC version folder under: $msvcRoot"
	}

	$cl = Join-Path $versionDir.FullName 'bin\Hostx64\x64\cl.exe'
	if (-not (Test-Path -LiteralPath $cl))
	{
		throw "cl.exe not found at: $cl"
	}

	return (Resolve-Path -LiteralPath $cl).Path
}

$repoRoot = Get-RepoRoot
$clExe = Find-MsvcClExe

$configMap = @{
	'Release|x64'   = @('Release x64')
	'Debug|x64'     = @('Debug x64')
	'Release|Win32' = @('Release Win32')
	'Debug|Win32'   = @('Debug Win32')
}
if (-not $configMap.ContainsKey($Configuration))
{
	throw "Unknown configuration '$Configuration'. Use Release|x64, Debug|x64, etc."
}

$intDirNames = $configMap[$Configuration]
$tlogFiles = @()
foreach ($dir in $intDirNames)
{
	$searchRoots = @(
		Join-Path $repoRoot "Envy\$dir"
		Join-Path $repoRoot "HashLib\$dir"
		Join-Path $repoRoot "TorrentEnvy\$dir"
	)
	foreach ($root in $searchRoots)
	{
		if (Test-Path -LiteralPath $root)
		{
			$tlogFiles += Get-ChildItem -LiteralPath $root -Recurse -Filter 'CL.command.*.tlog' -ErrorAction SilentlyContinue
		}
	}
}

if ($tlogFiles.Count -eq 0)
{
	throw "No CL.command.*.tlog found. Build Envy in Visual Studio ($Configuration) first."
}

$entries = @{}
foreach ($tlog in $tlogFiles)
{
	$projectDir = $tlog.Directory.Parent.Parent.FullName
	$lines = Get-Content -LiteralPath $tlog.FullName
	for ($i = 0; $i -lt $lines.Count - 1; $i++)
	{
		$srcLine = $lines[$i]
		if (-not $srcLine.StartsWith('^')) { continue }
		$src = $srcLine.Substring(1).Trim()
		$args = $lines[$i + 1].Trim()
		if ([string]::IsNullOrWhiteSpace($args)) { continue }
		$srcPath = [System.IO.Path]::GetFullPath($src)
		$command = "`"$clExe`" $args"
		$entries[$srcPath] = [ordered]@{
			directory = $projectDir
			file      = $srcPath
			command   = $command
		}
	}
}

$outPath = Join-Path $repoRoot 'compile_commands.json'
$json = $entries.Values | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($outPath, $json, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $($entries.Count) compile commands to $outPath (from $($tlogFiles.Count) tlog file(s), config $Configuration)."
