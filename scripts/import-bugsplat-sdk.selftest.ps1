#!/usr/bin/env pwsh
# Self-test for BugSplat SDK trust/import helpers (no real BugSplat SDK required).
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot 'lib\BugSplatSdkTrust.psm1'
Import-Module $modulePath -Force

function Assert-Throws {
	param([scriptblock]$Block, [string]$Pattern = '')
	try {
		& $Block
		throw 'Expected script block to throw'
	} catch {
		if ($Pattern -and $_.Exception.Message -notmatch $Pattern) {
			throw "Throw message mismatch. Expected pattern '$Pattern' got: $($_.Exception.Message)"
		}
	}
}

$tmp = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) ("bugsplat-trust-selftest-{0}" -f [guid]::NewGuid().Guid)) -Force

try {
	# CRT probe
	$mdLib = Join-Path $tmp.FullName 'md.lib'
	[System.IO.File]::WriteAllText($mdLib, 'DEFAULTLIB:msvcrt.lib DEFAULTLIB:msvcprt.lib')
	if ((Get-BugSplatStaticLibCrtKind -Path $mdLib) -ne 'md-dynamic-release') { throw 'md CRT probe failed' }
	$mtLib = Join-Path $tmp.FullName 'mt.lib'
	[System.IO.File]::WriteAllText($mtLib, 'DEFAULTLIB:LIBCMT')
	if ((Get-BugSplatStaticLibCrtKind -Path $mtLib) -ne 'mt-static-release') { throw 'mt CRT probe failed' }

	# Hash match / mismatch
	$refFile = Join-Path $tmp.FullName 'payload.bin'
	'hello' | Set-Content -LiteralPath $refFile -NoNewline
	$hash = Get-BugSplatFileSha256 -Path $refFile
	$map = @{ 'payload.bin' = $hash }
	Assert-BugSplatSourceMatchesReference -SourceFile $refFile -RelativePath 'payload.bin' -ReferenceMap $map | Out-Null
	'evil' | Set-Content -LiteralPath $refFile -NoNewline
	Assert-Throws { Assert-BugSplatSourceMatchesReference -SourceFile $refFile -RelativePath 'payload.bin' -ReferenceMap $map } -Pattern 'SHA-256 mismatch'

	# Empty reference map is fail-closed
	Assert-Throws { Assert-BugSplatSourceMatchesReference -SourceFile $refFile -RelativePath 'payload.bin' -ReferenceMap @{} } -Pattern 'no file entries'

	# Missing reference entry
	$map2 = @{ 'other.bin' = 'AA' }
	Assert-Throws { Assert-BugSplatSourceMatchesReference -SourceFile $refFile -RelativePath 'payload.bin' -ReferenceMap $map2 } -Pattern 'No reference hash'

	# Authenticode: unsigned PE must fail when required
	$fakeExe = Join-Path $tmp.FullName 'unsigned.exe'
	[System.IO.File]::WriteAllBytes($fakeExe, [byte[]](0x4D, 0x5A) + (,0 * 64))
	Assert-Throws { Assert-BugSplatAuthenticode -Path $fakeExe -RequireSignature:$true } -Pattern 'signature required'

	# import-bugsplat-sdk.ps1 must not accept removed bootstrap parameters
	$importScript = Join-Path $PSScriptRoot 'import-bugsplat-sdk.ps1'
	$importAst = [System.Management.Automation.Language.Parser]::ParseFile($importScript, [ref]$null, [ref]$null)
	$paramNames = $importAst.FindAll({ $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $true) |
		ForEach-Object { $_.Name.VariablePath.UserPath }
	if ($paramNames -contains 'RecordReferenceHashes' -or $paramNames -contains 'AllowUnlistedSource') {
		throw 'import-bugsplat-sdk.ps1 must not expose bootstrap-only parameters'
	}

	Write-Host 'import-bugsplat-sdk.selftest.ps1: all checks passed.' -ForegroundColor Green
} finally {
	Remove-Item -LiteralPath $tmp.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
