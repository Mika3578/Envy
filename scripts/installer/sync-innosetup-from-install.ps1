#Requires -Version 7.0
<#
.SYNOPSIS
  Refresh vendored Inno Setup Unicode compiler files from a local Inno Setup 6+ install.

.DESCRIPTION
  Copies the minimum ISCC payload into Installer/InnoSetup/. Run on a maintainer
  workstation after installing the pinned version documented in Version.txt.
  Not invoked by CI; CI uses the committed binaries.
#>
[CmdletBinding()]
param(
	[string]$SourceDir = "${env:ProgramFiles(x86)}\Inno Setup 6",
	[string]$DestDir = (Join-Path (git rev-parse --show-toplevel) 'Installer/InnoSetup')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath (Join-Path $SourceDir 'ISCC.exe'))) {
	throw "ISCC.exe not found under: $SourceDir"
}

$files = @(
	'ISCC.exe', 'ISCmplr.dll', 'ISPP.dll', 'ISPPBuiltins.iss', 'Default.isl', 'license.txt',
	'Setup.e32', 'SetupLdr.e32', 'SetupLdr.e64', 'SetupCustomStyle.e32',
	'islzma.dll', 'islzma32.exe', 'islzma64.exe',
	'is7z.dll', 'is7zxa.dll', 'is7zxr.dll',
	'isbunzip.dll', 'isbzip.dll', 'isunzlib.dll', 'iszlib.dll',
	'WizClassicImage.bmp', 'WizClassicSmallImage.bmp',
	'WizClassicImage-IS.bmp', 'WizClassicSmallImage-IS.bmp'
)

$sigFiles = @(
	'ISCmplr.dll.issig', 'ISPP.dll.issig', 'Setup.e32.issig', 'SetupLdr.e32.issig',
	'SetupLdr.e64.issig', 'SetupCustomStyle.e32.issig',
	'islzma.dll.issig', 'islzma32.exe.issig', 'islzma64.exe.issig',
	'is7z.dll.issig', 'is7zxa.dll.issig', 'is7zxr.dll.issig',
	'isbunzip.dll.issig', 'isbzip.dll.issig', 'isunzlib.dll.issig', 'iszlib.dll.issig'
)
$files += $sigFiles

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
foreach ($name in $files) {
	$src = Join-Path $SourceDir $name
	if (-not (Test-Path -LiteralPath $src)) {
		throw "Missing expected Inno file: $src"
	}
	$destName = if ($name -eq 'license.txt') { 'License.txt' } else { $name }
	Copy-Item -LiteralPath $src -Destination (Join-Path $DestDir $destName) -Force
}

Write-Host "Synced Inno Setup files to $DestDir"
