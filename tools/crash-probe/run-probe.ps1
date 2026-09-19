# Isolated Crashpad / Sentry Native probe for ENVY #90.
# Measures binary sizes, consent (upload off), and dump creation for
# av / heap / stack / fastfail. Not part of Envy.sln.
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$Exe,
	[Parameter(Mandatory = $true)]
	[ValidateSet('crashpad', 'sentry')]
	[string]$Backend,
	[string]$Handler,
	[string]$OutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Exe)) {
	throw "CrashProbe.exe not found: $Exe"
}

$exeItem = Get-Item -LiteralPath $Exe
$workRoot = if ($OutDir) { $OutDir } else { Join-Path $exeItem.DirectoryName 'probe-run' }
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null

function Find-Handler {
	param([string]$Hint)
	if ($Hint -and (Test-Path -LiteralPath $Hint)) { return (Get-Item -LiteralPath $Hint).FullName }
	$envHandler = $env:CRASH_PROBE_HANDLER
	if ($envHandler -and (Test-Path -LiteralPath $envHandler)) { return (Get-Item -LiteralPath $envHandler).FullName }
	$beside = Join-Path $exeItem.DirectoryName 'crashpad_handler.exe'
	if (Test-Path -LiteralPath $beside) { return (Get-Item -LiteralPath $beside).FullName }
	$searchRoots = @(
		(Join-Path $PSScriptRoot 'vcpkg_installed'),
		(Join-Path $exeItem.DirectoryName '..\..\vcpkg_installed')
	)
	foreach ($root in $searchRoots) {
		if (-not (Test-Path -LiteralPath $root)) { continue }
		$found = Get-ChildItem -Path $root -Recurse -Filter 'crashpad_handler.exe' -ErrorAction SilentlyContinue |
			Select-Object -First 1
		if ($found) { return $found.FullName }
	}
	throw 'crashpad_handler.exe not found (pass -Handler or set CRASH_PROBE_HANDLER)'
}

$handlerPath = Find-Handler -Hint $Handler
Copy-Item -LiteralPath $handlerPath -Destination (Join-Path $exeItem.DirectoryName 'crashpad_handler.exe') -Force

Get-ChildItem -Path (Split-Path -Parent $handlerPath) -Filter 'crashpad_wer*.dll' -ErrorAction SilentlyContinue |
	ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $exeItem.DirectoryName -Force }

$inventory = @()
Get-ChildItem -LiteralPath $exeItem.DirectoryName -File |
	Where-Object { $_.Extension -match '\.(exe|dll|pdb)$' } |
	ForEach-Object {
		$inventory += [pscustomobject]@{
			name = $_.Name
			bytes = $_.Length
		}
	}

$initDb = Join-Path $workRoot 'db-init'
New-Item -ItemType Directory -Force -Path $initDb | Out-Null
$initOut = & $exeItem.FullName --init-only --database $initDb --handler $handlerPath
$initText = ($initOut | Out-String)
Write-Host $initText
if ($LASTEXITCODE -ne 0) {
	throw "init-only failed with exit $LASTEXITCODE"
}
if ($initText -notmatch 'uploads_enabled=0') {
	throw 'consent failure: uploads_enabled is not 0'
}
if ($initText -match 'upload_url=\S') {
	throw 'consent failure: upload_url is not empty'
}

$crashKinds = @('av', 'heap', 'stack', 'fastfail')
$crashes = @()
foreach ($kind in $crashKinds) {
	$db = Join-Path $workRoot "db-$kind"
	New-Item -ItemType Directory -Force -Path $db | Out-Null
	$proc = Start-Process -FilePath $exeItem.FullName -ArgumentList @('--crash', $kind, '--database', $db, '--handler', $handlerPath) -PassThru -NoNewWindow -Wait
	Start-Sleep -Seconds 3
	$dumps = @(Get-ChildItem -Path $db -Recurse -Include *.dmp, *.mdmp -ErrorAction SilentlyContinue)
	$crashes += [pscustomobject]@{
		kind = $kind
		exit_code = $proc.ExitCode
		dump_count = $dumps.Count
		dump_bytes = (($dumps | Measure-Object -Property Length -Sum).Sum)
	}
}

$result = [pscustomobject]@{
	backend = $Backend
	exe = $exeItem.FullName
	handler = $handlerPath
	binaries = $inventory
	init = ($initText.Trim())
	crashes = $crashes
}

$jsonPath = Join-Path $workRoot 'measurements.json'
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding utf8
Write-Host "Wrote $jsonPath"

$failed = @($crashes | Where-Object { $_.dump_count -lt 1 })
if ($failed.Count -gt 0) {
	$names = ($failed | ForEach-Object { $_.kind }) -join ', '
	throw "No dump for crash kinds: $names"
}

Write-Host 'Crash probe passed (local dumps for av/heap/stack/fastfail).'
