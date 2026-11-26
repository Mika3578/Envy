#!/usr/bin/env pwsh
# Self-test for verify-runtime-dependencies.ps1 (no Windows/MSVC required; runs on Linux CI).
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$verifyScript = Join-Path $PSScriptRoot 'verify-runtime-dependencies.ps1'
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$samplePe = Join-Path $repoRoot 'Services/zlibwapi.64.dll'
if (-not (Test-Path -LiteralPath $samplePe -PathType Leaf))
{
	throw "Self-test sample PE not found: $samplePe"
}

$pwsh = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

function Invoke-Verify([string]$TreeDir)
{
	$output = & $pwsh -NoProfile -File $verifyScript -TreeDir $TreeDir 2>&1
	$text = ($output | ForEach-Object { "$_" }) -join "`n"
	return @{
		ExitCode = $LASTEXITCODE
		Output   = $text
	}
}

function Assert-Pass([string]$TreeDir, [string]$Label)
{
	$result = Invoke-Verify $TreeDir
	if ($result.ExitCode -ne 0)
	{
		throw "$Label expected PASS but failed (exit $($result.ExitCode)):`n$($result.Output)"
	}
	if ($result.Output -notmatch 'verify-runtime-dependencies: PASS')
	{
		throw "$Label did not print the PASS marker:`n$($result.Output)"
	}
}

function Assert-Fail([string]$TreeDir, [string]$Label, [string]$Pattern)
{
	$result = Invoke-Verify $TreeDir
	if ($result.ExitCode -eq 0)
	{
		throw "$Label expected FAIL but passed:`n$($result.Output)"
	}
	if ($Pattern -and $result.Output -notmatch $Pattern)
	{
		throw "$Label failure did not mention '$Pattern':`n$($result.Output)"
	}
}

function Copy-Tree([string]$Name)
{
	$dir = Join-Path $tmpRoot $Name
	New-Item -ItemType Directory -Force -Path $dir | Out-Null
	return $dir
}

# Latin-1 maps every byte to one char, so a string IndexOf yields the byte
# offset of the import-name entry we patch in the sample PE.
function Find-AsciiString([byte[]]$Bytes, [string]$Needle)
{
	$latin1 = [System.Text.Encoding]::GetEncoding(28591)
	$text = $latin1.GetString($Bytes)
	return $text.IndexOf($Needle, [System.StringComparison]::Ordinal)
}

# Build a minimal image whose only dependency is one import DLL name. The
# RVA form (grAttrs bit 0 set) is emitted as PE32+; the legacy preferred-base
# VA form only fits the 32-bit ImgDelayDescr fields of a PE32 image, which is
# written with a non-zero SectionAlignment so a wrong ImageBase read width
# cannot pass by accident. $NumberOfRvaAndSizes controls the data-directory
# count the parser must honor: a delay directory beyond that count must be
# ignored even though its bytes are present in the file. The switches add
# static-import tables and malformed shapes the parser must reject.
function New-SyntheticDelayImportPe([string]$Path, [string]$DelayDllName, [switch]$NameIsVa, [uint32]$NumberOfRvaAndSizes = 16, [switch]$BadImportDirRva, [switch]$BadDelayNameRva, [switch]$StaticImport, [switch]$NoDelay, [switch]$EmptyName, [switch]$UnterminatedName, [switch]$UnterminatedDir, [switch]$PartialStaticDescriptor, [switch]$PartialDelayDescriptor)
{
	if ($DelayDllName.Length -gt 200)
	{
		throw 'test delay DLL name too long'
	}
	if ($NameIsVa -and ($StaticImport -or $NoDelay -or $EmptyName -or $UnterminatedName -or $UnterminatedDir -or $PartialStaticDescriptor -or $PartialDelayDescriptor))
	{
		throw 'the static/malformed fixtures are only defined for the PE32+ RVA form'
	}
	$size = 0x400
	if ($UnterminatedName)
	{
		$size = 0x800
	}
	if ($UnterminatedDir)
	{
		$size = 0x14500
	}
	$bytes = New-Object 'byte[]' $size
	$bytes[0] = 0x4D
	$bytes[1] = 0x5A
	[BitConverter]::GetBytes([int32]0x80).CopyTo($bytes, 0x3C)
	$bytes[0x80] = 0x50
	$bytes[0x81] = 0x45
	$coff = 0x84
	$optional = 0x98
	[BitConverter]::GetBytes([uint16]1).CopyTo($bytes, $coff + 2)
	if ($NameIsVa)
	{
		$bytes[$coff] = 0x4C
		$bytes[$coff + 1] = 0x01
		[BitConverter]::GetBytes([uint16]224).CopyTo($bytes, $coff + 16)
		$bytes[$optional] = 0x0B
		$bytes[$optional + 1] = 0x01
		[BitConverter]::GetBytes([uint32]0x10000000).CopyTo($bytes, $optional + 28)
		[BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, $optional + 32)
		[BitConverter]::GetBytes($NumberOfRvaAndSizes).CopyTo($bytes, $optional + 92)
		$dataDirs = $optional + 96
		$sectionTable = $optional + 224
		$attributes = [uint32]0x0
		$nameRva = [uint32]0x10001040
	}
	else
	{
		$bytes[$coff] = 0x64
		$bytes[$coff + 1] = 0x86
		[BitConverter]::GetBytes([uint16]240).CopyTo($bytes, $coff + 16)
		$bytes[$optional] = 0x0B
		$bytes[$optional + 1] = 0x02
		[BitConverter]::GetBytes($NumberOfRvaAndSizes).CopyTo($bytes, $optional + 108)
		$dataDirs = $optional + 112
		$sectionTable = $optional + 240
		$attributes = [uint32]0x1
		$nameRva = [uint32]0x1040
	}
	# Non-zero export-directory RVA: the parser must not read directory 0, and
	# a too-wide NumberOfRvaAndSizes read would absorb it.
	[BitConverter]::GetBytes([uint32]0x1234).CopyTo($bytes, $dataDirs)
	if ($BadImportDirRva)
	{
		# Import directory that claims an RVA no section maps; the parser must
		# reject the image instead of treating it as having no imports.
		[BitConverter]::GetBytes([uint32]0x900000).CopyTo($bytes, $dataDirs + 1 * 8)
	}
	if ($StaticImport)
	{
		$staticDirRva = [uint32]0x1100
		if ($UnterminatedDir)
		{
			# 4096 descriptors follow at RVA 0x1200, none all-zero.
			$staticDirRva = [uint32]0x1200
		}
		[BitConverter]::GetBytes($staticDirRva).CopyTo($bytes, $dataDirs + 1 * 8)
		[BitConverter]::GetBytes([uint32]0x30).CopyTo($bytes, $dataDirs + 1 * 8 + 4)
	}
	if (-not $NoDelay)
	{
		[BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, $dataDirs + 13 * 8)
		[BitConverter]::GetBytes([uint32]0x40).CopyTo($bytes, $dataDirs + 13 * 8 + 4)
	}
	$section = $sectionTable
	[BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, $section + 8)
	[BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, $section + 12)
	[BitConverter]::GetBytes([uint32]($size - 0x200)).CopyTo($bytes, $section + 16)
	[BitConverter]::GetBytes([uint32]0x200).CopyTo($bytes, $section + 20)
	$data = 0x200
	if ($StaticImport)
	{
		if ($UnterminatedDir)
		{
			for ($i = 0; $i -lt 4096; $i++)
			{
				$descriptor = 0x400 + 20 * $i
				[BitConverter]::GetBytes([uint32]0x1060).CopyTo($bytes, $descriptor + 12)
			}
		}
		else
		{
			# RVA 0x1100 maps to file offset 0x300 (0x200 + 0x100).
			$staticEntry = 0x300
			$staticNameRva = [uint32]0x1060
			if ($EmptyName)
			{
				# Points at the zeroed delay-descriptor terminator area: a
				# resolvable RVA whose first byte is already the NUL.
				$staticNameRva = [uint32]0x1020
			}
			if ($UnterminatedName)
			{
				$staticNameRva = [uint32]0x1200
			}
			if ($PartialStaticDescriptor)
			{
				# Only FirstThunk is nonzero: not an all-zero terminator, but
				# the name field is zero and must fail the read.
				[BitConverter]::GetBytes([uint32]0x1180).CopyTo($bytes, $staticEntry + 16)
			}
			else
			{
				[BitConverter]::GetBytes([uint32]0x1180).CopyTo($bytes, $staticEntry)
				[BitConverter]::GetBytes($staticNameRva).CopyTo($bytes, $staticEntry + 12)
				[BitConverter]::GetBytes([uint32]0x1180).CopyTo($bytes, $staticEntry + 16)
			}
		}
		[System.Text.Encoding]::ASCII.GetBytes('STATICX.dll' + [char]0).CopyTo($bytes, 0x260)
	}
	if ($UnterminatedName)
	{
		# 513 non-NUL bytes: longer than the name scan bound.
		$fill = [System.Text.Encoding]::ASCII.GetBytes('A' * 513)
		$fill.CopyTo($bytes, 0x400)
	}
	if (-not $NoDelay)
	{
		$delayNameRva = if ($BadDelayNameRva) { [uint32]0x900000 } else { $nameRva }
		if ($PartialDelayDescriptor)
		{
			# Descriptor 1 is partially zeroed (module-handle field nonzero);
			# descriptor 2 is the real one and must still be reached.
			[BitConverter]::GetBytes([uint32]0x1).CopyTo($bytes, $data + 8)
			[BitConverter]::GetBytes($attributes).CopyTo($bytes, $data + 32)
			[BitConverter]::GetBytes($delayNameRva).CopyTo($bytes, $data + 36)
		}
		else
		{
			[BitConverter]::GetBytes($attributes).CopyTo($bytes, $data)
			[BitConverter]::GetBytes($delayNameRva).CopyTo($bytes, $data + 4)
		}
		$nameBytes = [System.Text.Encoding]::ASCII.GetBytes($DelayDllName + [char]0)
		$nameBytes.CopyTo($bytes, $data + 0x40)
	}
	[System.IO.File]::WriteAllBytes($Path, $bytes)
}

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runtime-deps-selftest-{0}" -f [guid]::NewGuid().Guid)
New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null
try
{
	# 1. A tree whose only image imports system DLLs passes.
	$tree = Copy-Tree 'system-only'
	Copy-Item -LiteralPath $samplePe -Destination (Join-Path $tree 'zlibwapi.dll')
	Assert-Pass $tree 'system-only tree'

	# 2. A first-party import the tree does not ship fails (the missing-HashLib.dll
	# artifact failure this check exists to catch).
	$tree = Copy-Tree 'missing-dep'
	$patched = [System.IO.File]::ReadAllBytes($samplePe)
	$found = Find-AsciiString $patched 'KERNEL32.dll'
	if ($found -lt 0)
	{
		throw 'Self-test sample does not contain the KERNEL32.dll import name'
	}
	$next = Find-AsciiString $patched[($found + 1)..($patched.Length - 1)] 'KERNEL32.dll'
	if ($next -ge 0)
	{
		throw 'Self-test sample contains more than one KERNEL32.dll occurrence; the byte patch would be ambiguous'
	}
	$replacement = [System.Text.Encoding]::ASCII.GetBytes('HASHLIBX.dll')
	for ($i = 0; $i -lt $replacement.Length; $i++)
	{
		$patched[$found + $i] = $replacement[$i]
	}
	[System.IO.File]::WriteAllBytes((Join-Path $tree 'zlibwapi.dll'), $patched)
	Assert-Fail $tree 'missing first-party dependency' 'HASHLIBX\.dll'

	# 3. The same tree passes once the dependency sits in the tree root.
	Copy-Item -LiteralPath $samplePe -Destination (Join-Path $tree 'HASHLIBX.dll')
	Assert-Pass $tree 'dependency present at tree root'

	# 4. A plugin image resolves dependencies from the tree root.
	$tree = Copy-Tree 'plugin-root-fallback'
	New-Item -ItemType Directory -Force -Path (Join-Path $tree 'Plugins') | Out-Null
	[System.IO.File]::WriteAllBytes((Join-Path $tree 'Plugins\zlibwapi.dll'), $patched)
	Copy-Item -LiteralPath $samplePe -Destination (Join-Path $tree 'HASHLIBX.dll')
	Assert-Pass $tree 'plugin resolves from tree root'

	# 5. Images that are not valid PE files fail closed.
	$tree = Copy-Tree 'broken-pe'
	Copy-Item -LiteralPath $samplePe -Destination (Join-Path $tree 'zlibwapi.dll')
	'not a PE' | Set-Content -LiteralPath (Join-Path $tree 'broken.dll') -NoNewline
	Assert-Fail $tree 'non-PE image' 'not a readable PE image'

	# 6. Delay-load imports are honored: missing delay DLL fails (PE32+ RVA form).
	$tree = Copy-Tree 'delay-missing'
	New-SyntheticDelayImportPe (Join-Path $tree 'delayhost.exe') 'DELAYX.dll'
	Assert-Fail $tree 'missing delay-load DLL' 'DELAYX\.dll'

	# 7. Shipped delay DLLs pass (PE32+ RVA name form).
	$tree = Copy-Tree 'delay-rva'
	New-SyntheticDelayImportPe (Join-Path $tree 'delayhost.exe') 'DELAYX.dll'
	Copy-Item -LiteralPath $samplePe -Destination (Join-Path $tree 'DELAYX.dll')
	Assert-Pass $tree 'delay-load DLL present (RVA form)'

	# 8. A PE32 image with a real SectionAlignment must rebase legacy VA names
	# correctly: a missing delay DLL fails, a shipped one passes.
	$tree = Copy-Tree 'delay-va-missing'
	New-SyntheticDelayImportPe (Join-Path $tree 'delayhost.exe') 'DELAYY.dll' -NameIsVa
	Assert-Fail $tree 'missing delay-load DLL (VA form)' 'DELAYY\.dll'

	$tree = Copy-Tree 'delay-va'
	New-SyntheticDelayImportPe (Join-Path $tree 'delayhost.exe') 'DELAYY.dll' -NameIsVa
	Copy-Item -LiteralPath $samplePe -Destination (Join-Path $tree 'DELAYY.dll')
	Assert-Pass $tree 'delay-load DLL present (VA form)'

	# 9. A delay directory beyond NumberOfRvaAndSizes is ignored even when its
	# bytes are present in the file, so the declared directory count is honored.
	$tree = Copy-Tree 'delay-beyond-count'
	New-SyntheticDelayImportPe (Join-Path $tree 'delayhost.exe') 'DELAYZ.dll' -NumberOfRvaAndSizes 2
	Assert-Pass $tree 'delay directory beyond the declared count is ignored'

	# 10. Malformed import metadata fails closed instead of counting as an
	# empty dependency set.
	$tree = Copy-Tree 'bad-import-dir'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -BadImportDirRva
	Assert-Fail $tree 'unmappable import directory' 'does not map into any image section'

	$tree = Copy-Tree 'bad-delay-name'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -BadDelayNameRva
	Assert-Fail $tree 'unmappable delay-load name' 'does not map into any image section'

	# 11. A well-formed static import table is walked end to end: a missing
	# DLL fails, a shipped one passes.
	$tree = Copy-Tree 'static-missing'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -StaticImport -NoDelay
	Assert-Fail $tree 'missing static import' 'STATICX\.dll'

	$tree = Copy-Tree 'static-present'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -StaticImport -NoDelay
	Copy-Item -LiteralPath $samplePe -Destination (Join-Path $tree 'STATICX.dll')
	Assert-Pass $tree 'static import resolved'

	# 12. Empty, unterminated, and unterminated-directory import tables fail
	# closed instead of scanning as empty.
	$tree = Copy-Tree 'empty-name'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -StaticImport -NoDelay -EmptyName
	Assert-Fail $tree 'empty import name' 'is empty'

	$tree = Copy-Tree 'unterminated-name'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -StaticImport -NoDelay -UnterminatedName
	Assert-Fail $tree 'unterminated import name' 'not NUL-terminated'

	$tree = Copy-Tree 'unterminated-dir'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -StaticImport -NoDelay -UnterminatedDir
	Assert-Fail $tree 'unterminated import directory' 'not terminated within 4096'

	# 13. A partially zeroed descriptor must not end a walk early: the parser
	# rejects the image instead of silently dropping later descriptors.
	$tree = Copy-Tree 'partial-static'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -StaticImport -NoDelay -PartialStaticDescriptor
	Assert-Fail $tree 'partially zeroed static descriptor' 'does not map into any image section'

	$tree = Copy-Tree 'partial-delay'
	New-SyntheticDelayImportPe (Join-Path $tree 'host.exe') 'DELAYX.dll' -PartialDelayDescriptor
	Assert-Fail $tree 'partially zeroed delay descriptor' 'does not map into any image section'

	# 14. A missing tree directory fails instead of passing silently.
	Assert-Fail (Join-Path $tmpRoot 'does-not-exist') 'missing tree directory' 'Runtime tree not found'
}
finally
{
	Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'verify-runtime-dependencies self-test: PASS'
exit 0
