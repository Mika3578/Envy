# Isolated Crashpad / Sentry Native probe for ENVY #90.
# Measures binary sizes, consent (upload off), and dump creation.
# Destructive crashes run in this disposable CrashProbe.exe process only.
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

function Get-DumpFiles {
	param([string]$Db)
	if (-not (Test-Path -LiteralPath $Db)) { return @() }
	return @(Get-ChildItem -Path $Db -Recurse -File -ErrorAction SilentlyContinue |
		Where-Object {
			$_.Name -eq 'minidump' -or
			$_.Extension -match '^\.(dmp|mdmp)$'
		})
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

$requiredKinds = @('av')
$optionalKinds = @('heap', 'stack', 'fastfail', 'terminate', 'invalid', 'multithread')
$crashKinds = $requiredKinds + $optionalKinds
$crashes = @()
foreach ($kind in $crashKinds) {
	$db = Join-Path $workRoot "db-$kind"
	New-Item -ItemType Directory -Force -Path $db | Out-Null
	$proc = Start-Process -FilePath $exeItem.FullName -ArgumentList @('--crash', $kind, '--database', $db, '--handler', $handlerPath) -PassThru -NoNewWindow -Wait
	Start-Sleep -Seconds 3
	$dumps = @(Get-DumpFiles -Db $db)
	$crashes += [pscustomobject]@{
		kind = $kind
		required = ($requiredKinds -contains $kind)
		exit_code = $proc.ExitCode
		dump_count = $dumps.Count
		dump_bytes = [int64](($dumps | Measure-Object -Property Length -Sum).Sum)
	}
}

$secondDb = Join-Path $workRoot 'db-av-second'
New-Item -ItemType Directory -Force -Path $secondDb | Out-Null
$second = Start-Process -FilePath $exeItem.FullName -ArgumentList @('--crash', 'av', '--database', $secondDb, '--handler', $handlerPath) -PassThru -NoNewWindow -Wait
Start-Sleep -Seconds 3
$secondDumps = @(Get-DumpFiles -Db $secondDb)
$crashes += [pscustomobject]@{
	kind = 'av-second'
	required = $true
	exit_code = $second.ExitCode
	dump_count = $secondDumps.Count
	dump_bytes = [int64](($secondDumps | Measure-Object -Property Length -Sum).Sum)
}

$noHandlerDb = Join-Path $workRoot 'db-no-handler'
New-Item -ItemType Directory -Force -Path $noHandlerDb | Out-Null
$noHandler = Start-Process -FilePath $exeItem.FullName -ArgumentList @('--crash', 'av', '--database', $noHandlerDb, '--no-handler') -PassThru -NoNewWindow -Wait
Start-Sleep -Seconds 2
$noHandlerDumps = @(Get-DumpFiles -Db $noHandlerDb)
$crashes += [pscustomobject]@{
	kind = 'no-handler'
	required = $false
	exit_code = $noHandler.ExitCode
	dump_count = $noHandlerDumps.Count
	dump_bytes = [int64](($noHandlerDumps | Measure-Object -Property Length -Sum).Sum)
}

$bogus = Join-Path $workRoot 'not-a-dir'
Set-Content -LiteralPath $bogus -Value 'not-a-directory' -Encoding ascii
$unwritable = Start-Process -FilePath $exeItem.FullName -ArgumentList @('--crash', 'av', '--database', $bogus, '--handler', $handlerPath) -PassThru -NoNewWindow -Wait
$crashes += [pscustomobject]@{
	kind = 'unwritable-db'
	required = $false
	exit_code = $unwritable.ExitCode
	dump_count = 0
	dump_bytes = 0
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

$failedRequired = @($crashes | Where-Object { $_.required -and $_.dump_count -lt 1 })
if ($failedRequired.Count -gt 0) {
	$names = ($failedRequired | ForEach-Object { $_.kind }) -join ', '
	throw "No dump for required crash kinds: $names"
}

if ($noHandlerDumps.Count -gt 0) {
	throw 'no-handler produced a dump in the probe database'
}

if ($unwritable.ExitCode -eq 0) {
	throw 'unwritable-db was expected to fail init'
}

Write-Host 'Crash probe passed (required local dumps; optional kinds recorded).'
