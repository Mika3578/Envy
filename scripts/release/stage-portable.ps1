#Requires -Version 7.0
<#
.SYNOPSIS
  Stage a portable Envy tree that mirrors the installer runtime layout.

.DESCRIPTION
  Builds artifacts/portable with:
  - Root binaries (Envy.exe, TorrentEnvy.exe, Unpacker.exe, service DLLs)
  - Plugins\ (plugin DLLs/EXEs + sidecars)
  - Data\, Schemas\, Skins\ (incl. Languages under Skins\Languages), Templates\, Remote\

  Aligns with Installer/Scripts/Main.iss Release packaging (no .pdb / Debug).
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[ValidateSet('x64', 'Win32')]
	[string]$Platform,

	[Parameter(Mandatory = $false)]
	[string]$RepoRoot = (Get-Location).Path,

	[Parameter(Mandatory = $false)]
	[string]$Destination = '',

	[Parameter(Mandatory = $false)]
	[string]$Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Fail([string]$Message)
{
	Write-Error $Message
	exit 1
}

function Ensure-Dir([string]$Path)
{
	New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Copy-FileRequired([string]$Source, [string]$DestDir, [string]$DestName = '')
{
	if (-not (Test-Path -LiteralPath $Source))
	{
		Write-Fail "Missing required file: $Source"
	}
	Ensure-Dir $DestDir
	$dest = if ($DestName) { Join-Path $DestDir $DestName } else { Join-Path $DestDir (Split-Path $Source -Leaf) }
	Copy-Item -LiteralPath $Source -Destination $dest -Force
	Write-Host "  + $dest"
}

function Copy-TreeFiltered
{
	param(
		[Parameter(Mandatory = $true)][string]$SourceDir,
		[Parameter(Mandatory = $true)][string]$DestDir,
		[string[]]$ExcludeNamePatterns = @(),
		[switch]$Recurse
	)

	if (-not (Test-Path -LiteralPath $SourceDir))
	{
		Write-Fail "Missing required directory: $SourceDir"
	}
	Ensure-Dir $DestDir

	$items = if ($Recurse)
	{
		Get-ChildItem -LiteralPath $SourceDir -Recurse -Force
	}
	else
	{
		Get-ChildItem -LiteralPath $SourceDir -Force
	}

	foreach ($item in $items)
	{
		$rel = $item.FullName.Substring((Resolve-Path -LiteralPath $SourceDir).Path.Length).TrimStart('\', '/')
		if (-not $rel)
		{
			continue
		}

		$skip = $false
		foreach ($pat in $ExcludeNamePatterns)
		{
			if ($item.Name -like $pat -or $rel -like $pat)
			{
				$skip = $true
				break
			}
		}
		if ($skip)
		{
			continue
		}

		$target = Join-Path $DestDir $rel
		if ($item.PSIsContainer)
		{
			Ensure-Dir $target
		}
		else
		{
			Ensure-Dir (Split-Path $target -Parent)
			Copy-Item -LiteralPath $item.FullName -Destination $target -Force
		}
	}
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$platformDir = "$Configuration $Platform"   # e.g. "Release x64"
$libGflPlat = if ($Platform -eq 'x64') { 'x64' } else { 'Win32' }

if (-not $Destination)
{
	$Destination = Join-Path $repo 'artifacts\portable'
}
$dest = $Destination
if (Test-Path -LiteralPath $dest)
{
	Remove-Item -LiteralPath $dest -Recurse -Force
}
Ensure-Dir $dest
Ensure-Dir (Join-Path $dest 'Plugins')

Write-Host "Staging portable layout for $platformDir -> $dest"

# --- Root executables ---
Copy-FileRequired (Join-Path $repo "Envy\$platformDir\Envy.exe") $dest
Copy-FileRequired (Join-Path $repo "TorrentEnvy\$platformDir\TorrentEnvy.exe") $dest
Copy-FileRequired (Join-Path $repo "Unpacker\$platformDir\Unpacker.exe") $dest

# --- Service / shared DLLs at app root (and selected copies under Plugins) ---
$serviceDlls = @(
	@{ Src = "Services\zlib\$platformDir\zlibwapi.dll"; AlsoPlugins = $true },
	@{ Src = "Services\Bzlib\$platformDir\Bzlib.dll"; AlsoPlugins = $false },
	@{ Src = "HashLib\$platformDir\HashLib.dll"; AlsoPlugins = $false },
	@{ Src = "Services\SQLite\$platformDir\SQLite.dll"; AlsoPlugins = $false },
	@{ Src = "Services\MiniUPnP\$platformDir\MiniUPnPc.dll"; AlsoPlugins = $false },
	@{ Src = "Services\GeoIP\$platformDir\GeoIP.dll"; AlsoPlugins = $false },
	@{ Src = "Services\LibGFL\$libGflPlat\LibGFL340.dll"; AlsoPlugins = $true }
)
foreach ($dll in $serviceDlls)
{
	$src = Join-Path $repo $dll.Src
	Copy-FileRequired $src $dest
	if ($dll.AlsoPlugins)
	{
		Copy-FileRequired $src (Join-Path $dest 'Plugins')
	}
}

# --- Plugins (Release outputs + sidecars) ---
$pluginProjects = @(
	'DocumentReader',
	'ImageViewer',
	'GFLImageServices',
	'GFLLibraryBuilder',
	'MediaImageServices',
	'MediaLibraryBuilder',
	'RARBuilder',
	'7ZipBuilder',
	'ZIPBuilder',
	'SkinScan',
	'SWFPlugin',
	'SearchExport',
	'ShortURL',
	'VirusTotal',
	'MediaPlayer'
)
$pluginsDest = Join-Path $dest 'Plugins'
foreach ($name in $pluginProjects)
{
	$built = Join-Path $repo "Plugins\$name\$platformDir"
	if (-not (Test-Path -LiteralPath $built))
	{
		Write-Fail "Missing plugin build output: $built"
	}
	Get-ChildItem -LiteralPath $built -File | Where-Object {
		$_.Extension -in '.dll', '.exe' -and $_.Extension -ne '.pdb' -and $_.Name -notlike '*.pdb'
	} | ForEach-Object {
		Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $pluginsDest $_.Name) -Force
		Write-Host "  + Plugins\$($_.Name)"
	}
}

# WindowsThumbnail is an .exe helper
$thumb = Join-Path $repo "Plugins\WindowsThumbnail\$platformDir\WindowsThumbnail.exe"
if (Test-Path -LiteralPath $thumb)
{
	Copy-FileRequired $thumb $pluginsDest
}

# WebHook ships both bitnesses (matches Inno)
foreach ($wh in @(
	(Join-Path $repo "Plugins\WebHook\$Configuration Win32\WebHook32.dll"),
	(Join-Path $repo "Plugins\WebHook\$Configuration x64\WebHook64.dll")
))
{
	if (Test-Path -LiteralPath $wh)
	{
		Copy-FileRequired $wh $pluginsDest
	}
	else
	{
		Write-Host "  ! optional missing: $wh"
	}
}

# Sidecars
if ($Platform -eq 'x64')
{
	Copy-FileRequired (Join-Path $repo 'Plugins\RARBuilder\Unrar64.dll') $pluginsDest
	Copy-FileRequired (Join-Path $repo 'Plugins\7ZipBuilder\7zxa.64.dll') $pluginsDest '7zxa.dll'
}
else
{
	Copy-FileRequired (Join-Path $repo 'Plugins\RARBuilder\Unrar.dll') $pluginsDest
	Copy-FileRequired (Join-Path $repo 'Plugins\7ZipBuilder\7zxa.dll') $pluginsDest
}

# Optional helper bats
foreach ($bat in @('Services\SaveSettings.bat', 'Services\RestoreSettings.bat'))
{
	$p = Join-Path $repo $bat
	if (Test-Path -LiteralPath $p)
	{
		Copy-FileRequired $p $dest
	}
}

$license = Join-Path $repo 'Installer\License\License (AGPLv3).html'
if (Test-Path -LiteralPath $license)
{
	Copy-FileRequired $license $dest
}

# --- Runtime resource trees (shared, platform-independent) ---
Copy-TreeFiltered -SourceDir (Join-Path $repo 'Data') -DestDir (Join-Path $dest 'Data') `
	-ExcludeNamePatterns @('.svn', '*.bak', '*.bak.*', '*GPL*', 'WorldGPS.xml')

Copy-TreeFiltered -SourceDir (Join-Path $repo 'Schemas') -DestDir (Join-Path $dest 'Schemas') `
	-ExcludeNamePatterns @('.svn', '*.bak', 'ReadMe.txt', 'SchemaDescriptor.xsd')
# Inno includes *.Safe.ico for Win32 only; ship them for both portable packages.
Get-ChildItem -LiteralPath (Join-Path $repo 'Schemas') -Filter '*.Safe.ico' -File -ErrorAction SilentlyContinue |
	ForEach-Object {
		Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $dest "Schemas\$($_.Name)") -Force
	}

Copy-TreeFiltered -SourceDir (Join-Path $repo 'Skins') -DestDir (Join-Path $dest 'Skins') -Recurse `
	-ExcludeNamePatterns @('.svn', '*.bak', '*.bak.*')

# Languages live under Skins\Languages (Inno DestDir), with en.xml -> en.defaults
$langDest = Join-Path $dest 'Skins\Languages'
Ensure-Dir $langDest
Get-ChildItem -LiteralPath (Join-Path $repo 'Languages') -Filter '*.ico' -File | ForEach-Object {
	Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $langDest $_.Name) -Force
}
Get-ChildItem -LiteralPath (Join-Path $repo 'Languages') -Filter '*.xml' -File | ForEach-Object {
	if ($_.Name -eq 'en.xml')
	{
		Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $langDest 'en.defaults') -Force
	}
	else
	{
		Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $langDest $_.Name) -Force
	}
}
Write-Host "  + Skins\Languages ($((Get-ChildItem $langDest -File | Measure-Object).Count) files)"

Copy-TreeFiltered -SourceDir (Join-Path $repo 'Templates') -DestDir (Join-Path $dest 'Templates') -Recurse `
	-ExcludeNamePatterns @('.svn', '*.bak')

Copy-TreeFiltered -SourceDir (Join-Path $repo 'Remote') -DestDir (Join-Path $dest 'Remote') `
	-ExcludeNamePatterns @('.svn', '*.xlsx', 'Readme.txt')

# Sanity: no pdb / Debug leftovers
$bad = @(Get-ChildItem -LiteralPath $dest -Recurse -File | Where-Object {
	$_.Extension -eq '.pdb' -or $_.FullName -match '[\\/]Debug[\\/]'
})
if ($bad.Count -gt 0)
{
	Write-Fail ("Portable stage contains forbidden files: " + (($bad | ForEach-Object { $_.FullName }) -join ', '))
}

$required = @(
	'Envy.exe',
	'TorrentEnvy.exe',
	'Unpacker.exe',
	'Data',
	'Schemas',
	'Skins',
	'Skins\Languages',
	'Templates',
	'Remote',
	'Plugins'
)
foreach ($req in $required)
{
	$path = Join-Path $dest $req
	if (-not (Test-Path -LiteralPath $path))
	{
		Write-Fail "Portable stage missing required path: $req"
	}
}
if (-not (Test-Path -LiteralPath (Join-Path $dest 'Skins\Languages\en.defaults')))
{
	Write-Fail 'Portable stage missing Skins\Languages\en.defaults'
}
if (-not (Get-ChildItem (Join-Path $dest 'Data') -File -ErrorAction SilentlyContinue | Select-Object -First 1))
{
	Write-Fail 'Portable stage Data\ is empty'
}

$fileCount = (Get-ChildItem -LiteralPath $dest -Recurse -File | Measure-Object).Count
Write-Host "stage-portable: PASS ($fileCount files under $dest)"
exit 0
