#!/usr/bin/env pwsh
# Self-test for BugSplat VC runtime copy helpers (no MSVC install required on Linux).
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot (Join-Path 'lib' 'EnvyVcTools.psm1')
Import-Module $modulePath -Force

function Join-MultiPath {
	param(
		[Parameter(Mandatory, ValueFromRemainingArguments = $true)]
		[string[]]$Segment
	)
	$path = $Segment[0]
	foreach ($part in $Segment[1..($Segment.Length - 1)]) {
		$path = Join-Path $path $part
	}
	return $path
}

function Assert-Throws {
	param([scriptblock]$Block, [string]$Pattern = '')
	$threw = $false
	try {
		& $Block
	} catch {
		$threw = $true
		if ($Pattern -and $_.Exception.Message -notmatch $Pattern) {
			throw "Throw message mismatch. Expected pattern '$Pattern' got: $($_.Exception.Message)"
		}
	}
	if (-not $threw) {
		throw 'Expected script block to throw'
	}
}

$tmp = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) ("bugsplat-vc-runtime-selftest-{0}" -f [guid]::NewGuid().Guid)) -Force
$savedVcToolsInstallDir = $env:VCToolsInstallDir
$savedVcToolsVersion = $env:VCToolsVersion
$pathSep = if ($IsWindows) { ';' } else { ':' }

try {
	$env:VCToolsInstallDir = $null
	$env:VCToolsVersion = $null
	# Get-EnvyVcToolsInstallDir prefers explicit parameter over env
	$fakeTools = Join-MultiPath $tmp.FullName 'VC' 'Tools' 'MSVC' '14.50.00000'
	New-Item -ItemType Directory -Path (Join-MultiPath $fakeTools 'bin' 'Hostx64' 'x64') -Force | Out-Null
	$resolved = Get-EnvyVcToolsInstallDir -VcToolsInstallDir $fakeTools
	if ($resolved -ne $fakeTools) { throw 'VcToolsInstallDir parameter resolution failed' }

	# Get-EnvyDumpBinPath resolves under fake tree
	$dumpbin = Join-MultiPath $fakeTools 'bin' 'Hostx64' 'x64' 'dumpbin.exe'
	'stub' | Set-Content -LiteralPath $dumpbin -NoNewline
	$found = Get-EnvyDumpBinPath -VcToolsInstallDir $fakeTools
	if ($found -ne $dumpbin) { throw 'Get-EnvyDumpBinPath did not prefer VCToolsInstallDir layout' }

	# CopyBugSplatVcRuntime.ps1 must fail closed when dumpbin is missing
	$copyScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Envy/CopyBugSplatVcRuntime.ps1'
	$dest = Join-Path $tmp.FullName 'Debug x64'
	New-Item -ItemType Directory -Path $dest -Force | Out-Null
	'pe' | Set-Content -LiteralPath (Join-Path $dest 'BugSplatMonitor.exe') -NoNewline
	Assert-Throws {
		& $copyScript -Configuration Debug -Platform x64 -VcToolsInstallDir (Join-Path $tmp.FullName 'missing-tools') -DestOverride $dest -DisableToolchainFallback
	} -Pattern 'dumpbin\.exe was not found'

	# verify-bugsplat-output-layout.ps1 must fail closed when monitor present but dumpbin missing
	$verifyScript = Join-Path $PSScriptRoot 'verify-bugsplat-output-layout.ps1'
	Assert-Throws {
		& $verifyScript -OutputDir $dest -VcToolsInstallDir (Join-Path $tmp.FullName 'missing-tools') -DisableToolchainFallback
	} -Pattern 'dumpbin\.exe was not found'

	# Redist discovery: fake VS root with Tools + Redist layouts
	$vsRoot = Join-Path $tmp.FullName 'VSRoot'
	$toolsVer = Join-MultiPath $vsRoot 'VC' 'Tools' 'MSVC' '14.50.35710'
	New-Item -ItemType Directory -Path (Join-MultiPath $toolsVer 'bin' 'Hostx64' 'x64') -Force | Out-Null
	$redistVer = Join-MultiPath $vsRoot 'VC' 'Redist' 'MSVC' '14.50.35710'
	$redistRel = Join-MultiPath $redistVer 'x64' 'Microsoft.VC145.CRT'
	$redistDbg = Join-MultiPath $redistVer 'debug_nonredist' 'x64' 'Microsoft.VC145.DebugCRT'
	New-Item -ItemType Directory -Path $redistRel -Force | Out-Null
	New-Item -ItemType Directory -Path $redistDbg -Force | Out-Null
	'x' | Set-Content -LiteralPath (Join-Path $redistRel 'vcruntime140.dll') -NoNewline
	'x' | Set-Content -LiteralPath (Join-Path $redistDbg 'vcruntime140d.dll') -NoNewline
	$gotRel = Get-EnvyVcRedistDllDir -VcToolsInstallDir $toolsVer
	$gotDbg = Get-EnvyVcDebugRedistDllDir -VcToolsInstallDir $toolsVer
	if (-not $gotRel -or -not (Test-Path -LiteralPath (Join-Path $gotRel 'vcruntime140.dll'))) {
		throw "Get-EnvyVcRedistDllDir failed under fake tree (got '$gotRel')"
	}
	if (-not $gotDbg -or -not (Test-Path -LiteralPath (Join-Path $gotDbg 'vcruntime140d.dll'))) {
		throw "Get-EnvyVcDebugRedistDllDir failed under fake tree (got '$gotDbg')"
	}

	# A valid-but-dumpbinless explicit toolchain dir fails closed under strict
	# fallback even when another dumpbin is reachable via PATH, and falls back
	# to PATH only when fallback is enabled.
	$bareTools = Join-MultiPath $tmp.FullName 'VC' 'Tools' 'MSVC' '14.50.99999'
	New-Item -ItemType Directory -Path (Join-MultiPath $bareTools 'bin' 'Hostx64' 'x64') -Force | Out-Null
	$pathDumpbin = Join-MultiPath $tmp.FullName 'path-dumpbin'
	New-Item -ItemType Directory -Path $pathDumpbin -Force | Out-Null
	$stubName = if ($IsWindows) { 'dumpbin.exe' } else { 'dumpbin' }
	$stubPath = Join-Path $pathDumpbin $stubName
	'stub' | Set-Content -LiteralPath $stubPath -NoNewline
	if (-not $IsWindows) { & chmod +x -- $stubPath }
	$savedPath = $env:PATH
	try {
		$env:PATH = "$pathDumpbin$pathSep$env:PATH"
		if ($null -ne (Get-EnvyDumpBinPath -VcToolsInstallDir $bareTools -DisableFallback)) {
			throw 'Strict fallback must not resolve dumpbin outside the explicit toolchain'
		}
		if ((Get-EnvyDumpBinPath -VcToolsInstallDir $bareTools) -notlike "$pathDumpbin*") {
			throw 'Non-strict fallback should resolve dumpbin via PATH'
		}
	} finally {
		$env:PATH = $savedPath
	}

	# Case-insensitive dumpbin dependent classification (uppercase PE import names).
	# Lint runs this self-test on ubuntu-latest; .cmd is not executable there.
	if ($IsWindows) {
		$fakeDump = Join-Path $tmp.FullName 'fake-dumpbin.cmd'
		@'
@echo off
echo Image has the following dependencies:
echo.
echo     VCRUNTIME140D.dll
echo     MSVCP140D.dll
echo     ucrtbased.dll
'@ | Set-Content -LiteralPath $fakeDump -Encoding ascii
	} else {
		$fakeDump = Join-Path $tmp.FullName 'fake-dumpbin.sh'
		@'
#!/bin/sh
echo Image has the following dependencies:
echo
echo     VCRUNTIME140D.dll
echo     MSVCP140D.dll
echo     ucrtbased.dll
'@ | Set-Content -LiteralPath $fakeDump -Encoding ascii
		& chmod +x -- $fakeDump
	}
	$deps = Get-BugSplatMonitorMsvcDependents -MonitorPath (Join-Path $dest 'BugSplatMonitor.exe') -DumpBinPath $fakeDump
	if ($deps.Count -lt 3) {
		throw "Expected uppercase dumpbin imports to classify; got: $($deps -join ',')"
	}

	$required = Get-BugSplatOutputRequiredDlls -MonitorPath (Join-Path $dest 'BugSplatMonitor.exe') -DumpBinPath $fakeDump -Configuration Debug -Platform x64
	if ($required -notcontains 'vcruntime140_1d.dll') {
		throw "Debug x64 output must include installer CRT names not always reported by dumpbin; got: $($required -join ',')"
	}

	$requiredRelease = Get-BugSplatOutputRequiredDlls -MonitorPath (Join-Path $dest 'BugSplatMonitor.exe') -DumpBinPath $fakeDump -Configuration Release -Platform x64
	foreach ($dll in Get-BugSplatReleaseX64InstallerCrtDllNames) {
		if ($requiredRelease -notcontains $dll) {
			throw "Release x64 output must include retail CRT satellite names not reported by dumpbin; got: $($requiredRelease -join ',')"
		}
	}

	# Windows API-set imports are system contracts, not redistributable DLL files.
	$stubText = Get-Content -LiteralPath $fakeDump -Raw
	$stubText += "`necho     API-MS-WIN-CRT-RUNTIME-L1-1-0.dll`necho     KERNEL32.dll`n"
	$stubText | Set-Content -LiteralPath $fakeDump -Encoding ascii
	$deps = @(Get-BugSplatMonitorMsvcDependents -MonitorPath (Join-Path $dest 'BugSplatMonitor.exe') -DumpBinPath $fakeDump)
	if ($deps.Count -ne 3) { throw "Unexpected dependent filtering: $($deps -join ',')" }

	# Empty and single-import output keep the fixed packaging contract intact.
	foreach ($imports in @('', 'echo     VCRUNTIME140.dll')) {
		$prefix = if ($IsWindows) { "@echo off`n" } else { "#!/bin/sh`n" }
		($prefix + $imports + "`nexit 0`n") | Set-Content -LiteralPath $fakeDump -Encoding ascii
		$minimal = @(Get-BugSplatOutputRequiredDlls -MonitorPath (Join-Path $dest 'BugSplatMonitor.exe') -DumpBinPath $fakeDump -Configuration Release -Platform x64)
		if ($minimal.Count -ne 5 -or $minimal -notcontains 'vcruntime140.dll') {
			throw "Empty/single-import output broke the Release packaging contract: $($minimal -join ',')"
		}
	}

	# A failed inspection must never be interpreted as an empty dependency list.
	$stubText += "`nexit 7`n"
	$stubText | Set-Content -LiteralPath $fakeDump -Encoding ascii
	Assert-Throws {
		Get-BugSplatMonitorMsvcDependents -MonitorPath (Join-Path $dest 'BugSplatMonitor.exe') -DumpBinPath $fakeDump
	} -Pattern 'dumpbin /dependents failed.*exit 7'

	# Reject incomplete SDK staging before inspecting CRT dependencies.
	Assert-Throws {
		& $verifyScript -OutputDir $dest -VcToolsInstallDir $fakeTools -DisableToolchainFallback
	} -Pattern 'Missing required BugSplat runtime: BugSplatWer.dll'
	'pe' | Set-Content -LiteralPath (Join-Path $dest 'BugSplatWer.dll') -NoNewline
	Assert-Throws {
		& $verifyScript -OutputDir $dest -VcToolsInstallDir $fakeTools -DisableToolchainFallback
	} -Pattern 'Missing required BugSplat runtime: BugSplatRc.dll'
	$emptyOutput = Join-Path $tmp.FullName 'Release x64'
	New-Item -ItemType Directory -Path $emptyOutput -Force | Out-Null
	Assert-Throws {
		& $verifyScript -OutputDir $emptyOutput -VcToolsInstallDir $fakeTools -DisableToolchainFallback
	} -Pattern 'Missing required BugSplat runtime: BugSplatMonitor.exe'

	# Do not select x86 or OneCore CRTs when the desktop v145 tree exists.
	foreach ($subdir in @('x86', 'onecore/x64')) {
		$wrong = Join-MultiPath $redistVer $subdir 'Microsoft.VC145.CRT'
		New-Item -ItemType Directory -Path $wrong -Force | Out-Null
		'wrong' | Set-Content -LiteralPath (Join-Path $wrong 'vcruntime140.dll') -NoNewline
	}
	if ((Get-EnvyVcRedistDllDir -VcToolsInstallDir $toolsVer) -ne $redistRel) {
		throw 'Redist discovery must prefer the desktop x64 CRT'
	}
	$fallbackTools = Join-MultiPath $tmp.FullName 'fallback' 'VC' 'Tools' 'MSVC' '14.50.00000'
	$fallbackCrt = Join-MultiPath $fallbackTools 'bin' 'Hostx64' 'x64'
	New-Item -ItemType Directory -Path $fallbackCrt -Force | Out-Null
	'x' | Set-Content -LiteralPath (Join-Path $fallbackCrt 'vcruntime140.dll') -NoNewline
	$newerCrt = Join-MultiPath (Split-Path $fallbackTools -Parent) '14.59.99999' 'bin' 'Hostx64' 'x64'
	New-Item -ItemType Directory -Path $newerCrt -Force | Out-Null
	'wrong' | Set-Content -LiteralPath (Join-Path $newerCrt 'vcruntime140.dll') -NoNewline
	if ((Get-EnvyVcRedistDllDir -VcToolsInstallDir $fallbackTools) -ne $fallbackCrt) {
		throw 'Redist discovery must support the active tool-local CRT fallback'
	}

	Write-Host 'copy-bugsplat-vc-runtime.selftest.ps1: OK'
} finally {
	$env:VCToolsInstallDir = $savedVcToolsInstallDir
	$env:VCToolsVersion = $savedVcToolsVersion
	Remove-Item -LiteralPath $tmp.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
