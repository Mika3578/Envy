# Regression coverage for local checkout selection without cloning or installing packages.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$parseTokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
	(Join-Path $PSScriptRoot 'bootstrap-vcpkg.ps1'),
	[ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$resolver = $ast.Find({
	param($node)
	$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
		$node.Name -eq 'Resolve-VcpkgExe'
}, $false)
if (-not $resolver) { throw 'Resolve-VcpkgExe was not found' }
. ([scriptblock]::Create($resolver.Extent.Text))

function Install-LocalVcpkg {
	param([string]$Root)
	$script:installCalls++
	return (Join-Path $Root 'vcpkg/vcpkg.exe')
}

function Find-ExistingVcpkg {
	param([string]$Root)
	$script:findCalls++
	return $script:externalExe
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('envy-vcpkg-selection-' + [guid]::NewGuid())
if (Test-Path -LiteralPath $testRoot) { throw 'Expected an absent local checkout' }

foreach ($external in @('external-vcpkg.exe', '')) {
	$script:externalExe = $external
	$script:installCalls = 0
	$script:findCalls = 0
	$result = Resolve-VcpkgExe -Root $testRoot -AllowClone
	if ($result -ne (Join-Path $testRoot 'vcpkg/vcpkg.exe') -or
		$script:installCalls -ne 1 -or $script:findCalls -ne 0) {
		throw '-AllowClone must select the pinned local checkout even before it exists'
	}
}

$script:externalExe = 'external-vcpkg.exe'
$script:installCalls = 0
$script:findCalls = 0
$result = Resolve-VcpkgExe -Root $testRoot
if ($result -ne $script:externalExe -or $script:installCalls -ne 0 -or $script:findCalls -ne 1) {
	throw 'Without -AllowClone, an existing executable must remain usable'
}

$script:externalExe = ''
$script:installCalls = 0
$script:findCalls = 0
$missingRejected = $false
try { Resolve-VcpkgExe -Root $testRoot | Out-Null }
catch {
	if ($_.Exception.Message -notlike '*vcpkg.exe was not found*') { throw }
	$missingRejected = $true
}
if (-not $missingRejected -or $script:installCalls -ne 0 -or $script:findCalls -ne 1) {
	throw 'Without -AllowClone, a missing executable must fail without cloning'
}

Write-Host 'bootstrap-vcpkg selection: 4 cases passed'
