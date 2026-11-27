#Requires -Version 7.0
<#
.SYNOPSIS
  Verify packaged release assets before draft upload.

.DESCRIPTION
  Checks expected names, non-zero sizes, SHA256SUMS.txt contents against the
  four binaries, ZIP extractability, absence of .pdb/Debug payloads, presence
  of Envy.exe inside each portable ZIP, the required root runtime files per
  platform, and that every packaged PE import resolves inside the tree
  (verify-runtime-dependencies.ps1).
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$ReleaseDir,

	[Parameter(Mandatory = $true)]
	[string]$Version,

	[Parameter(Mandatory = $false)]
	[bool]$RequireWin32 = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Fail([string]$Message)
{
	Write-Error $Message
	exit 1
}

function Get-Sha256Hex([string]$Path)
{
	$hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
	return $hash.Hash.ToLowerInvariant()
}

$version = $Version.Trim()
if ($version.StartsWith('v'))
{
	$version = $version.Substring(1)
}

$dir = (Resolve-Path -LiteralPath $ReleaseDir).Path
Write-Host "Verifying release assets in $dir (version=$version)"

$expected = @(
	"Envy-$version-x64.zip",
	"Envy-$version-x64-setup.exe",
	"SHA256SUMS.txt"
)
if ($RequireWin32)
{
	$expected = @(
		"Envy-$version-x64.zip",
		"Envy-$version-x64-setup.exe",
		"Envy-$version-win32.zip",
		"Envy-$version-win32-setup.exe",
		'SHA256SUMS.txt'
	)
}

$present = Get-ChildItem -LiteralPath $dir -File | Select-Object -ExpandProperty Name
foreach ($name in $expected)
{
	$path = Join-Path $dir $name
	if (-not (Test-Path -LiteralPath $path))
	{
		Write-Fail "Missing expected asset: $name"
	}
	$item = Get-Item -LiteralPath $path
	if ($item.Length -le 0)
	{
		Write-Fail "Asset has zero size: $name"
	}
	Write-Host ("  present {0} ({1:N0} bytes)" -f $name, $item.Length)
}

$unexpected = @($present | Where-Object { $_ -notin $expected })
if ($unexpected.Count -gt 0)
{
	Write-Host "Note: extra files in release dir (allowed): $($unexpected -join ', ')"
}

$sumsPath = Join-Path $dir 'SHA256SUMS.txt'
$sumLines = Get-Content -LiteralPath $sumsPath | Where-Object { $_.Trim() -ne '' }
$sumMap = @{}
foreach ($line in $sumLines)
{
	# GNU coreutils: "<hex>  <filename>" or "<hex> *<filename>"
	if ($line -notmatch '^(?<hash>[0-9a-fA-F]{64})\s+\*?(?<file>\S+)\s*$')
	{
		Write-Fail "Malformed SHA256SUMS line: $line"
	}
	$file = $Matches['file']
	$hash = $Matches['hash'].ToLowerInvariant()
	if ($sumMap.ContainsKey($file))
	{
		Write-Fail "Duplicate checksum entry for $file"
	}
	$sumMap[$file] = $hash
}

$binaries = @($expected | Where-Object { $_ -ne 'SHA256SUMS.txt' })
foreach ($name in $binaries)
{
	if (-not $sumMap.ContainsKey($name))
	{
		Write-Fail "SHA256SUMS.txt is missing entry for $name"
	}
	$actual = Get-Sha256Hex (Join-Path $dir $name)
	if ($actual -ne $sumMap[$name])
	{
		Write-Fail "Checksum mismatch for $name`n  expected $($sumMap[$name])`n  actual   $actual"
	}
	Write-Host "  checksum OK $name"
}

foreach ($key in @($sumMap.Keys))
{
	if ($key -eq 'SHA256SUMS.txt')
	{
		continue
	}
	if ($key -notin $binaries)
	{
		Write-Fail "SHA256SUMS.txt lists unexpected file: $key"
	}
}

$zipNames = @($binaries | Where-Object { $_ -like '*.zip' })
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("envy-release-verify-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
try
{
	foreach ($zipName in $zipNames)
	{
		$zipPath = Join-Path $dir $zipName
		$extractDir = Join-Path $tempRoot ($zipName -replace '\.zip$', '')
		New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
		try
		{
			Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
		}
		catch
		{
			Write-Fail "ZIP is not extractable: $zipName ($_)"
		}

		$envyExe = Join-Path $extractDir 'Envy.exe'
		if (-not (Test-Path -LiteralPath $envyExe))
		{
			Write-Fail "ZIP $zipName does not contain Envy.exe at archive root"
		}

		$requiredDirs = @('Data', 'Schemas', 'Skins', 'Plugins', 'Templates', 'Remote')
		foreach ($dirName in $requiredDirs)
		{
			$path = Join-Path $extractDir $dirName
			if (-not (Test-Path -LiteralPath $path))
			{
				Write-Fail "ZIP $zipName missing required runtime directory: $dirName"
			}
		}
		$enDefaults = Join-Path $extractDir 'Skins\Languages\en.defaults'
		if (-not (Test-Path -LiteralPath $enDefaults))
		{
			Write-Fail "ZIP $zipName missing Skins\Languages\en.defaults (languages not staged)"
		}
		$dataFiles = @(Get-ChildItem -LiteralPath (Join-Path $extractDir 'Data') -File -ErrorAction SilentlyContinue)
		if ($dataFiles.Count -eq 0)
		{
			Write-Fail "ZIP $zipName has empty Data\ directory"
		}
		$pluginFiles = @(Get-ChildItem -LiteralPath (Join-Path $extractDir 'Plugins') -File -ErrorAction SilentlyContinue)
		if ($pluginFiles.Count -eq 0)
		{
			Write-Fail "ZIP $zipName has empty Plugins\ directory"
		}

		# Flattened-only packages (previous bug) put plugin DLLs next to Envy.exe.
		$rootDlls = @(Get-ChildItem -LiteralPath $extractDir -Filter '*.dll' -File -ErrorAction SilentlyContinue)
		$suspiciousFlat = @($rootDlls | Where-Object {
			$_.Name -match '^(DocumentReader|ImageViewer|MediaPlayer|SearchExport)\.dll$'
		})
		if ($suspiciousFlat.Count -gt 0)
		{
			Write-Fail ("ZIP {0} looks flattened (plugin DLLs at archive root): {1}" -f $zipName, (($suspiciousFlat | ForEach-Object Name) -join ', '))
		}

		$pdb = @(Get-ChildItem -LiteralPath $extractDir -Recurse -Filter '*.pdb' -File -ErrorAction SilentlyContinue)
		if ($pdb.Count -gt 0)
		{
			Write-Fail ("ZIP {0} contains .pdb files: {1}" -f $zipName, (($pdb | ForEach-Object { $_.Name }) -join ', '))
		}

		$debugHits = @(Get-ChildItem -LiteralPath $extractDir -Recurse -File -ErrorAction SilentlyContinue |
			Where-Object { $_.FullName -match '[\\/]Debug[\\/]' })
		if ($debugHits.Count -gt 0)
		{
			Write-Fail "ZIP $zipName contains Debug-path files."
		}

		$platform = if ($zipName -match '-x64\.zip$') { 'x64' }
		elseif ($zipName -match '-win32\.zip$') { 'Win32' }
		else { $null }
		if (-not $platform)
		{
			Write-Fail "ZIP name does not identify a platform: $zipName"
		}

		# Deterministic runtime bundle: the root must carry the first-party
		# service DLLs and the platform crash-reporting runtime, not just
		# Envy.exe. OrdinalIgnoreCase because packaging extracts on Linux.
		$rootNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
		Get-ChildItem -LiteralPath $extractDir -File | ForEach-Object { $rootNames.Add($_.Name) | Out-Null }
		$requiredRootFiles = @(
			'TorrentEnvy.exe',
			'Unpacker.exe',
			'zlibwapi.dll',
			'Bzlib.dll',
			'HashLib.dll',
			'SQLite.dll',
			'MiniUPnPc.dll',
			'GeoIP.dll',
			'LibGFL340.dll'
		)
		if ($platform -eq 'x64')
		{
			# BugSplatMonitor.exe is a /MD PE: without its CRT companions the
			# crash reporter cannot start on a clean machine.
			$requiredRootFiles += @(
				'BugSplatMonitor.exe',
				'BugSplatWer.dll',
				'BugSplatRc.dll',
				'vcruntime140.dll',
				'vcruntime140_1.dll',
				'msvcp140.dll',
				'msvcp140_1.dll',
				'msvcp140_2.dll'
			)
		}
		else
		{
			$requiredRootFiles += 'crashpad_handler.exe'
		}
		$absent = @($requiredRootFiles | Where-Object { -not $rootNames.Contains($_) })
		if ($absent.Count -gt 0)
		{
			Write-Fail ("ZIP {0} missing required runtime files: {1}" -f $zipName, ($absent -join ', '))
		}

		# Every packaged image's imports must resolve inside the tree, not on
		# the tester's machine.
		& (Join-Path $PSScriptRoot 'verify-runtime-dependencies.ps1') -TreeDir $extractDir

		Write-Host "  zip OK $zipName (runtime tree present, no pdb/Debug)"
	}
}
finally
{
	Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($setup in @($binaries | Where-Object { $_ -like '*-setup.exe' }))
{
	$setupPath = Join-Path $dir $setup
	$bytes = [System.IO.File]::ReadAllBytes($setupPath)
	# MZ header
	if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A)
	{
		Write-Fail "Setup is not a PE executable (missing MZ): $setup"
	}
	Write-Host "  setup OK $setup (MZ header)"
}

Write-Host 'verify-artifacts: PASS'
exit 0
