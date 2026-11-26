#Requires -Version 7.0
<#
.SYNOPSIS
  Verify that every non-system DLL imported by the PE images in a runtime tree
  resolves to a file inside that tree.

.DESCRIPTION
  Parses the PE import table (static import directory and delay-load import
  directory) of every .exe/.dll under -TreeDir with a pure PowerShell reader,
  so it runs on Windows build agents and on the Linux release packaging job
  alike (no dumpbin / Visual Studio tooling required). An import is resolved
  when a file of the same name exists next to the importing image, in the tree
  root, or under Plugins\ - the search locations the packaged application
  relies on. Imports that Windows always resolves from the operating system
  are skipped through the system allowlist.

  This is the check that keeps release and live-test artifacts directly
  runnable: adding a new first-party runtime dependency without staging it
  fails CI instead of failing on a user machine with "DLL was not found".
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$TreeDir,

	# Windows 10 1809+ inbox DLLs: the loader resolves these from the OS, so
	# they are not required inside the tree. Redistributable runtime DLLs
	# (vcruntime140*, msvcp140*, concrt140, vcomp140) are deliberately NOT
	# listed: whenever a packaged image imports them, the tree must ship them.
	[string[]]$SystemDlls = @(
		'advapi32.dll', 'apphelp.dll', 'authz.dll', 'bcrypt.dll', 'bcryptprimitives.dll',
		'cfgmgr32.dll', 'clbcatq.dll', 'combase.dll', 'comctl32.dll', 'comdlg32.dll',
		'crypt32.dll', 'cryptbase.dll', 'cryptsp.dll', 'cabinet.dll', 'dbghelp.dll',
		'dbgcore.dll', 'devobj.dll', 'd2d1.dll', 'd3d9.dll', 'd3d11.dll', 'dcomp.dll',
		'dwmapi.dll', 'dxgi.dll', 'dwrite.dll', 'gdi32.dll', 'gdiplus.dll', 'imagehlp.dll',
		'imm32.dll', 'iphlpapi.dll', 'kernel32.dll', 'kernelbase.dll', 'mscoree.dll',
		'msi.dll', 'msimg32.dll', 'msvcrt.dll', 'netapi32.dll', 'normaliz.dll', 'ntdll.dll',
		'ntmarta.dll', 'ole32.dll', 'oleacc.dll', 'oleaut32.dll', 'oledlg.dll', 'powrprof.dll',
		'propsys.dll', 'psapi.dll', 'rasapi32.dll', 'rasman.dll', 'rpcrt4.dll', 'sechost.dll',
		'setupapi.dll', 'shcore.dll', 'shell32.dll', 'shlwapi.dll', 'sspcli.dll', 'sspicli.dll',
		'tapi32.dll', 'ucrtbase.dll', 'urlmon.dll', 'user32.dll', 'userenv.dll', 'usp10.dll',
		'uxtheme.dll', 'fontsub.dll', 'version.dll', 'winhttp.dll', 'wininet.dll', 'winmm.dll',
		'winspool.drv', 'winscard.dll', 'wintrust.dll', 'wldp.dll', 'ws2_32.dll', 'wsock32.dll',
		'wtsapi32.dll', 'xmllite.dll',
		'api-ms-', 'ext-ms-'
	)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Fail([string]$Message)
{
	Write-Error $Message
	exit 1
}

<#
.SYNOPSIS
  Read the PE import table (static + delay-load) of an image.
#>
function Get-PeImportedDllNames([byte[]]$Bytes)
{
	if ($Bytes.Length -lt 0x40)
	{
		throw 'file too small for a PE image'
	}
	if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A)
	{
		throw 'missing MZ signature'
	}
	$peOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
	if ($peOffset -lt 0 -or ($peOffset + 4 + 20) -gt $Bytes.Length)
	{
		throw 'COFF header out of bounds'
	}
	if ($Bytes[$peOffset] -ne 0x50 -or $Bytes[$peOffset + 1] -ne 0x45 -or $Bytes[$peOffset + 2] -ne 0 -or $Bytes[$peOffset + 3] -ne 0)
	{
		throw 'missing PE signature'
	}

	$coff = $peOffset + 4
	$sectionCount = [BitConverter]::ToUInt16($Bytes, $coff + 2)
	$optionalSize = [BitConverter]::ToUInt16($Bytes, $coff + 16)
	$optional = $coff + 20
	if ($optionalSize -lt 68 -or ($optional + $optionalSize) -gt $Bytes.Length)
	{
		throw 'optional header out of bounds'
	}

	$magic = [BitConverter]::ToUInt16($Bytes, $optional)
	if ($magic -eq 0x20B)
	{
		$dataDirs = $optional + 112
		$dirCount = [BitConverter]::ToInt64($Bytes, $optional + 108)
		$imageBase = [BitConverter]::ToInt64($Bytes, $optional + 24)
	}
	elseif ($magic -eq 0x10B)
	{
		$dataDirs = $optional + 96
		$dirCount = [BitConverter]::ToUInt32($Bytes, $optional + 92)
		$imageBase = [BitConverter]::ToInt64($Bytes, $optional + 28)
	}
	else
	{
		throw ("unsupported optional header magic 0x{0:X4}" -f $magic)
	}
	if ($dataDirs + 16 * 8 -gt $Bytes.Length)
	{
		throw 'data directories out of bounds'
	}

	$sectionTable = $optional + $optionalSize
	if ($sectionTable + 40 * $sectionCount -gt $Bytes.Length)
	{
		throw 'section table out of bounds'
	}
	$sections = @()
	for ($i = 0; $i -lt $sectionCount; $i++)
	{
		$entry = $sectionTable + 40 * $i
		$virtualSize = [BitConverter]::ToUInt32($Bytes, $entry + 8)
		$virtualAddress = [BitConverter]::ToUInt32($Bytes, $entry + 12)
		$rawSize = [BitConverter]::ToUInt32($Bytes, $entry + 16)
		$rawPointer = [BitConverter]::ToUInt32($Bytes, $entry + 20)
		$extent = [Math]::Max($virtualSize, $rawSize)
		$sections += ,@([int64]$virtualAddress, [int64]$extent, [int64]$rawPointer)
	}

	function Convert-RvaToOffset([int64]$Rva)
	{
		foreach ($section in $sections)
		{
			if ($Rva -ge $section[0] -and $Rva -lt ($section[0] + $section[1]))
			{
				$offset = $section[2] + ($Rva - $section[0])
				if ($offset -lt 0 -or $offset -ge $Bytes.Length)
				{
					return $null
				}
				return $offset
			}
		}
		return $null
	}

	function Read-ImportNameRva([int64]$Rva)
	{
		$offset = Convert-RvaToOffset $Rva
		if ($null -eq $offset)
		{
			return $null
		}
		$end = $offset
		while ($end -lt $Bytes.Length -and $Bytes[$end] -ne 0 -and ($end - $offset) -lt 512)
		{
			$end++
		}
		if ($end -ge $Bytes.Length -or ($end - $offset) -ge 512)
		{
			return $null
		}
		return [System.Text.Encoding]::ASCII.GetString($Bytes, $offset, $end - $offset)
	}

	function Read-ImportDirectoryRva([int]$Index)
	{
		if ($dirCount -le $Index)
		{
			return [int64]0
		}
		return [BitConverter]::ToUInt32($Bytes, $dataDirs + $Index * 8)
	}

	$names = @()

	# Static import directory: IMAGE_IMPORT_DESCRIPTOR (20 bytes), Name RVA at +12.
	$importRva = Read-ImportDirectoryRva 1
	if ($importRva -ne 0)
	{
		$offset = Convert-RvaToOffset $importRva
		for ($i = 0; $null -ne $offset -and $i -lt 4096; $i++)
		{
			$entry = $offset + 20 * $i
			if ($entry + 20 -gt $Bytes.Length)
			{
				throw 'static import directory out of bounds'
			}
			if ([BitConverter]::ToUInt32($Bytes, $entry) -eq 0 -and [BitConverter]::ToUInt32($Bytes, $entry + 12) -eq 0)
			{
				break
			}
			$name = Read-ImportNameRva ([BitConverter]::ToUInt32($Bytes, $entry + 12))
			if ($name)
			{
				$names += $name
			}
		}
	}

	# Delay-load import directory: ImgDelayDescr (32 bytes); with the
	# dlattrRva attribute (grAttrs bit 0) the name field is an RVA, otherwise
	# a preferred-base VA that must be rebased.
	$delayRva = Read-ImportDirectoryRva 13
	if ($delayRva -ne 0)
	{
		$offset = Convert-RvaToOffset $delayRva
		for ($i = 0; $null -ne $offset -and $i -lt 4096; $i++)
		{
			$entry = $offset + 32 * $i
			if ($entry + 32 -gt $Bytes.Length)
			{
				throw 'delay import directory out of bounds'
			}
			$attributes = [BitConverter]::ToUInt32($Bytes, $entry)
			$nameField = [BitConverter]::ToUInt32($Bytes, $entry + 4)
			if ($attributes -eq 0 -and $nameField -eq 0)
			{
				break
			}
			$nameRva = if ($attributes -band 0x1) { [int64]$nameField } else { [int64]$nameField - $imageBase }
			$name = Read-ImportNameRva $nameRva
			if ($name)
			{
				$names += $name
			}
		}
	}

	return ,$names
}

$resolvedTree = Resolve-Path -LiteralPath $TreeDir -ErrorAction SilentlyContinue
if (-not $resolvedTree)
{
	Write-Fail "Runtime tree not found: $TreeDir"
}
$tree = $resolvedTree.Path

$peFiles = @(Get-ChildItem -LiteralPath $tree -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' })
if ($peFiles.Count -eq 0)
{
	Write-Fail "No .exe/.dll images found under $tree; refusing to pass an empty runtime tree"
}

# Full-path lookup table (OrdinalIgnoreCase like the Windows loader) for the
# candidate directories: beside the importing image, tree root, Plugins\.
$resolved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($file in $peFiles)
{
	$resolved.Add("$($file.DirectoryName)\$($file.Name)") | Out-Null
}
$treeRoot = $tree
$pluginsDir = Join-Path $tree 'Plugins'

$parseFailures = @()
$missing = @()
$importTotal = 0
foreach ($file in $peFiles)
{
	$bytes = [System.IO.File]::ReadAllBytes($file.FullName)
	try
	{
		$imports = Get-PeImportedDllNames $bytes
	}
	catch
	{
		$parseFailures += "$($file.FullName): not a readable PE image ($($_.Exception.Message))"
		continue
	}

	$importTotal += $imports.Count
	$imageDir = $file.DirectoryName
	foreach ($name in $imports)
	{
		$lower = $name.ToLowerInvariant()
		$isSystem = $false
		foreach ($entry in $SystemDlls)
		{
			$pattern = $entry.ToLowerInvariant()
			if ($lower -eq $pattern -or ($pattern.EndsWith('-') -and $lower.StartsWith($pattern)))
			{
				$isSystem = $true
				break
			}
		}
		if ($isSystem)
		{
			continue
		}
		if ($resolved.Contains("$imageDir\$name") -or
			$resolved.Contains("$treeRoot\$name") -or
			$resolved.Contains("$pluginsDir\$name"))
		{
			continue
		}
		$missing += "$($file.FullName) imports $name (not beside the image, in the tree root, or under Plugins\)"
	}
}

if ($parseFailures.Count -gt 0)
{
	Write-Fail ("Unreadable PE images in runtime tree:`n  " + ($parseFailures -join "`n  "))
}
if ($missing.Count -gt 0)
{
	Write-Fail ("Unresolved DLL imports in runtime tree:`n  " + ($missing -join "`n  "))
}

Write-Host "verify-runtime-dependencies: PASS ($($peFiles.Count) images, $importTotal imports under $tree)"
exit 0
