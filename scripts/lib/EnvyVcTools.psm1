# Visual Studio / MSVC tool discovery for Envy build scripts (fail-closed helpers).
Set-StrictMode -Version Latest

function Join-MultiPath {
	param(
		[Parameter(Mandatory, ValueFromRemainingArguments = $true)]
		[string[]]$Segment
	)
	if ($Segment.Length -lt 1) {
		throw 'Join-MultiPath requires at least one path segment'
	}
	$path = $Segment[0]
	foreach ($part in $Segment[1..($Segment.Length - 1)]) {
		$path = Join-Path $path $part
	}
	return $path
}

function Get-EnvyVsInstallPath {
	$programFilesX86 = ${env:ProgramFiles(x86)}
	if (-not $programFilesX86) { return $null }
	$vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
	if (-not (Test-Path -LiteralPath $vswhere)) { return $null }
	$install = (& $vswhere -latest -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -as [string]
	if (-not $install) { return $null }
	return $install.TrimEnd('\')
}

function Get-EnvyVcToolsInstallDir {
	param(
		[string]$VcToolsInstallDir
	)

	if ($VcToolsInstallDir) {
		$VcToolsInstallDir = $VcToolsInstallDir.TrimEnd('\')
		if (Test-Path -LiteralPath $VcToolsInstallDir) { return $VcToolsInstallDir }
	}
	if ($env:VCToolsInstallDir) {
		$fromEnv = $env:VCToolsInstallDir.TrimEnd('\')
		if (Test-Path -LiteralPath $fromEnv) { return $fromEnv }
	}

	$install = Get-EnvyVsInstallPath
	if (-not $install) { return $null }

	if ($env:VCToolsVersion) {
		$candidate = Join-MultiPath $install 'VC' 'Tools' 'MSVC' $env:VCToolsVersion
		if (Test-Path -LiteralPath $candidate) { return $candidate }
	}

	$toolsRoot = Join-MultiPath $install 'VC' 'Tools' 'MSVC'
	if (-not (Test-Path -LiteralPath $toolsRoot)) { return $null }
	$latest = Get-ChildItem -LiteralPath $toolsRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
	if ($latest) { return $latest.FullName }
	return $null
}

function Get-EnvyDumpBinPath {
	param(
		[string]$VcToolsInstallDir,
		[string[]]$HostArchCandidates = @('x64', 'x86'),
		[switch]$DisableFallback
	)

	$toolsDir = $null
	if ($VcToolsInstallDir -and -not (Test-Path -LiteralPath $VcToolsInstallDir) -and $DisableFallback) {
		return $null
	}
	$toolsDir = Get-EnvyVcToolsInstallDir -VcToolsInstallDir $VcToolsInstallDir
	if ($toolsDir) {
		foreach ($hostArch in $HostArchCandidates) {
			$path = Join-MultiPath $toolsDir 'bin' "Host$hostArch" 'x64' 'dumpbin.exe'
			if (Test-Path -LiteralPath $path) { return $path }
		}
	}
	if ($DisableFallback) { return $null }

	$cmd = Get-Command dumpbin -ErrorAction SilentlyContinue
	if ($cmd -and (Test-Path -LiteralPath $cmd.Source)) { return $cmd.Source }

	$install = Get-EnvyVsInstallPath
	if ($install) {
		$dumpbin = Get-ChildItem -Path (Join-MultiPath $install 'VC' 'Tools' 'MSVC') -Recurse -Filter 'dumpbin.exe' -ErrorAction SilentlyContinue |
			Where-Object { $_.FullName -match '[/\\]Hostx(?:64|86)[/\\]x64[/\\]dumpbin\.exe$' } |
			Sort-Object FullName -Descending |
			Select-Object -First 1
		if ($dumpbin) { return $dumpbin.FullName }
	}
	return $null
}

function Find-VcRedistDllDirUnderMsvcRoot {
	param([string]$MsvcRoot)
	foreach ($ver in Get-ChildItem -LiteralPath $MsvcRoot -Directory | Sort-Object Name -Descending) {
		$candidates = @(
			(Join-MultiPath $ver.FullName 'vc_redist.x64' 'Microsoft.VC143.CRT'),
			(Join-MultiPath $ver.FullName 'vc_redist.x64' 'Microsoft.VC142.CRT'),
			(Join-MultiPath $ver.FullName 'x64' 'Microsoft.VC143.CRT'),
			(Join-MultiPath $ver.FullName 'Microsoft.VC143.CRT')
		)
		$candidates += @(Get-ChildItem -LiteralPath $ver.FullName -Directory -Recurse -ErrorAction SilentlyContinue |
			Where-Object { $_.Name -match '^Microsoft\.VC\d+\.CRT$' -and $_.FullName -match '[/\\]x64[/\\]' -and $_.FullName -notmatch '[/\\]onecore[/\\]' } |
			Sort-Object FullName -Descending |
			Select-Object -ExpandProperty FullName)
		foreach ($c in $candidates) {
			if (Test-Path -LiteralPath (Join-Path $c 'vcruntime140.dll')) { return $c }
		}
	}
	$hit = Get-ChildItem -LiteralPath $MsvcRoot -Recurse -Filter 'vcruntime140.dll' -File -ErrorAction SilentlyContinue |
		Where-Object { ($_.FullName -match '[/\\]x64[/\\]' -or $_.FullName -match 'vc_redist\.x64') -and $_.FullName -notmatch '[/\\]onecore[/\\]' } |
		Sort-Object FullName -Descending |
		Select-Object -First 1
	if ($hit) { return $hit.DirectoryName }
	return $null
}

function Find-VcRedistDllDirUnderToolsDir {
	param([string]$ToolsRoot)
	$hostBin = Join-MultiPath $ToolsRoot 'bin' 'Hostx64' 'x64'
	if (Test-Path -LiteralPath (Join-Path $hostBin 'vcruntime140.dll')) {
		return $hostBin
	}
	return $null
}

function Get-EnvyVcRedistDllDir {
	param([string]$VcToolsInstallDir)

	$toolsDir = Get-EnvyVcToolsInstallDir -VcToolsInstallDir $VcToolsInstallDir
	$install = $null
	if ($toolsDir) {
		$install = Split-Path (Split-Path (Split-Path (Split-Path $toolsDir -Parent) -Parent) -Parent) -Parent
	}
	if (-not $install) { $install = Get-EnvyVsInstallPath }
	if (-not $install) { return $null }

	$msvcRoot = Join-MultiPath $install 'VC' 'Redist' 'MSVC'
	if (Test-Path -LiteralPath $msvcRoot) {
		$fromRedist = Find-VcRedistDllDirUnderMsvcRoot -MsvcRoot $msvcRoot
		if ($fromRedist) { return $fromRedist }
	}

	if ($toolsDir) {
		return Find-VcRedistDllDirUnderToolsDir -ToolsRoot $toolsDir
	}

	return $null
}

function Get-EnvyVcDebugRedistDllDir {
	param([string]$VcToolsInstallDir)

	$toolsDir = Get-EnvyVcToolsInstallDir -VcToolsInstallDir $VcToolsInstallDir
	$install = $null
	if ($toolsDir) {
		$install = Split-Path (Split-Path (Split-Path (Split-Path $toolsDir -Parent) -Parent) -Parent) -Parent
	}
	if (-not $install) { $install = Get-EnvyVsInstallPath }
	if (-not $install) { return $null }

	$msvcRoot = Join-MultiPath $install 'VC' 'Redist' 'MSVC'
	if (-not (Test-Path -LiteralPath $msvcRoot)) { return $null }
	foreach ($ver in Get-ChildItem -LiteralPath $msvcRoot -Directory | Sort-Object Name -Descending) {
		$candidates = @(
			(Join-MultiPath $ver.FullName 'debug_nonredist' 'x64' 'Microsoft.VC143.DebugCRT'),
			(Join-MultiPath $ver.FullName 'debug_nonredist' 'x64' 'Microsoft.VC142.DebugCRT')
		)
		$candidates += @(Get-ChildItem -LiteralPath $ver.FullName -Directory -Recurse -ErrorAction SilentlyContinue |
			Where-Object {
				$_.Name -match '^Microsoft\.VC\d+\.DebugCRT$' -and
				$_.FullName -match '[/\\]x64[/\\]'
			} |
			Sort-Object FullName -Descending |
			Select-Object -ExpandProperty FullName)
		foreach ($candidate in $candidates) {
			if (Test-Path -LiteralPath $candidate) { return $candidate }
		}
	}
	return $null
}

function Get-EnvyWindowsSdkUcrtDllPath {
	param(
		[string]$Name = 'ucrtbase.dll'
	)

	$programFilesX86 = ${env:ProgramFiles(x86)}
	if (-not $programFilesX86) { return $null }

	if ($Name -ieq 'ucrtbased.dll') {
		$binRoot = Join-MultiPath $programFilesX86 'Windows Kits' '10' 'bin'
		if (-not (Test-Path -LiteralPath $binRoot)) { return $null }
		foreach ($version in Get-ChildItem -LiteralPath $binRoot -Directory | Sort-Object Name -Descending) {
			$candidate = Join-MultiPath $version.FullName 'x64' 'ucrt' $Name
			if (Test-Path -LiteralPath $candidate) { return $candidate }
		}
		$candidate = Join-MultiPath $binRoot 'x64' 'ucrt' $Name
		if (Test-Path -LiteralPath $candidate) { return $candidate }
		return $null
	}

	if ($Name -ieq 'ucrtbase.dll') {
		$redistRoot = Join-MultiPath $programFilesX86 'Windows Kits' '10' 'Redist'
		if (-not (Test-Path -LiteralPath $redistRoot)) { return $null }
		foreach ($version in Get-ChildItem -LiteralPath $redistRoot -Directory | Sort-Object Name -Descending) {
			$candidate = Join-MultiPath $version.FullName 'ucrt' 'DLLs' 'x64' $Name
			if (Test-Path -LiteralPath $candidate) { return $candidate }
		}
		$candidate = Join-MultiPath $redistRoot 'ucrt' 'DLLs' 'x64' $Name
		if (Test-Path -LiteralPath $candidate) { return $candidate }
		return $null
	}

	return $null
}

function Get-BugSplatDebugX64InstallerCrtDllNames {
	# msvcp140_1d.dll / msvcp140_2d.dll are loaded at runtime by msvcp140d.dll and
	# never appear in an import table, so dumpbin /dependents cannot report them;
	# the debug workflow fail-closes on the complete debug set anyway.
	return @(
		'vcruntime140d.dll',
		'vcruntime140_1d.dll',
		'msvcp140d.dll',
		'msvcp140_1d.dll',
		'msvcp140_2d.dll',
		'ucrtbased.dll'
	)
}

function Get-BugSplatReleaseX64InstallerCrtDllNames {
	# msvcp140_1.dll / msvcp140_2.dll are loaded at runtime by msvcp140.dll and
	# never appear in an import table, so dumpbin /dependents cannot report them;
	# the release workflow fail-closes on the complete retail set anyway.
	return @(
		'vcruntime140.dll',
		'vcruntime140_1.dll',
		'msvcp140.dll',
		'msvcp140_1.dll',
		'msvcp140_2.dll'
	)
}

function Get-BugSplatOutputRequiredDlls {
	param(
		[string]$MonitorPath,
		[string]$DumpBinPath,
		[string]$Configuration,
		[string]$Platform
	)

	$needed = @(Get-BugSplatMonitorMsvcDependents -MonitorPath $MonitorPath -DumpBinPath $DumpBinPath)
	foreach ($name in @('BugSplatWer.dll', 'BugSplatRc.dll')) {
		$companion = Join-Path (Split-Path $MonitorPath -Parent) $name
		if (Test-Path -LiteralPath $companion -PathType Leaf) {
			$needed += @(Get-BugSplatMonitorMsvcDependents -MonitorPath $companion -DumpBinPath $DumpBinPath)
		}
	}
	if ($Platform -ieq 'x64') {
		$installerCrt = if ($Configuration -ieq 'Debug') {
			Get-BugSplatDebugX64InstallerCrtDllNames
		} else {
			Get-BugSplatReleaseX64InstallerCrtDllNames
		}
		$seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
		foreach ($dll in $needed) { $seen.Add($dll) | Out-Null }
		foreach ($dll in $installerCrt) { $seen.Add($dll) | Out-Null }
		return @($seen) | Sort-Object
	}
	return $needed
}

function Get-BugSplatMonitorMsvcDependents {
	param(
		[string]$MonitorPath,
		[string]$DumpBinPath
	)

	if (-not (Test-Path -LiteralPath $MonitorPath)) {
		throw "BugSplat monitor not found: $MonitorPath"
	}
	if (-not $DumpBinPath) {
		throw 'DumpBinPath is required'
	}
	if (-not (Test-Path -LiteralPath $DumpBinPath)) {
		throw "dumpbin not found at $DumpBinPath"
	}

	$depOut = & $DumpBinPath /nologo /dependents $MonitorPath 2>&1 | Out-String
	if ($LASTEXITCODE -ne 0) {
		throw "dumpbin /dependents failed on $MonitorPath (exit $LASTEXITCODE): $depOut"
	}

	$needed = @()
	foreach ($line in ($depOut -split '\r?\n')) {
		$name = $line.Trim()
		# API-set imports are provided by Windows 10; only app-local CRT files are staged.
		if ($name -imatch '^(?:concrt|msvcp|ucrtbase|vcruntime|vcomp).*\.dll$') {
			# Preserve dumpbin casing for filesystem lookups; classify case-insensitively.
			$needed += $name
		}
	}
	return @($needed | Sort-Object -Unique)
}

Export-ModuleMember -Function @(
	'Get-EnvyVsInstallPath',
	'Get-EnvyVcToolsInstallDir',
	'Get-EnvyDumpBinPath',
	'Get-EnvyVcRedistDllDir',
	'Get-EnvyVcDebugRedistDllDir',
	'Get-EnvyWindowsSdkUcrtDllPath',
	'Get-BugSplatDebugX64InstallerCrtDllNames',
	'Get-BugSplatReleaseX64InstallerCrtDllNames',
	'Get-BugSplatMonitorMsvcDependents',
	'Get-BugSplatOutputRequiredDlls'
)
