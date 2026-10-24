<#
.SYNOPSIS
  Runs a short, isolated Envy Kad test and writes an anonymised report.

.DESCRIPTION
  Never modifies your installed Envy, its Data folder, HostCache.dat or the registry.
  1. Checks that the registry does not point a new copy at your personal data (read only).
  2. Copies the build folder to a new test folder and starts the COPY from there.
  3. Waits, then collects Envy.log of the copy and writes a report with IPs, paths,
     hashes and e-mail addresses replaced by placeholders.

  Settings such as DebugLog are stored in the registry, so a copy shares them with your
  installation. This script therefore does NOT change them: enable them in the Envy
  Settings window (see docs/10_dev/kad-windows-test.md). For a fully separate registry use
  Windows Sandbox (New-KadSandboxConfig.ps1).

.PARAMETER BuildFolder
  Folder that contains Envy.exe from the CI artifact (the whole folder is copied).
.PARAMETER Minutes
  How long to let Envy run before the report is made (default 10).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BuildFolder,
    [int]$Minutes = 10
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Fail([string]$Message) { Write-Host "STOP: $Message" -ForegroundColor Red; exit 1 }

$exeSource = Join-Path $BuildFolder 'Envy.exe'
if (-not (Test-Path -LiteralPath $exeSource)) { Fail "Envy.exe not found in '$BuildFolder'." }
if ($Minutes -lt 3 -or $Minutes -gt 60) { Fail 'Minutes must be between 3 and 60.' }
if (Get-Process -Name 'Envy' -ErrorAction SilentlyContinue) {
    Fail 'Envy is already running. Close every Envy window first, then run this script again.'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$testRoot = Join-Path $env:USERPROFILE "EnvyKadTest\$stamp"
$copy = Join-Path $testRoot 'envy'
$testRootFull = [System.IO.Path]::GetFullPath($testRoot)

# Read-only check of the registry values that decide where Envy keeps its data. Envy reads
# each value from HKCU and falls back to HKLM (the installer writes MultiUser there).
$shared = @()
foreach ($regKey in 'HKCU:\Software\Envy\Envy', 'HKLM:\Software\Envy\Envy') {
    if (-not (Test-Path $regKey)) { continue }
    $item = Get-ItemProperty -Path $regKey
    foreach ($name in 'Path', 'UserPath', 'DataPath') {
        $prop = $item.PSObject.Properties[$name]
        if ($prop -and $prop.Value) {
            $full = [System.IO.Path]::GetFullPath([string]$prop.Value)
            if (-not $full.StartsWith($testRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                $shared += "$regKey $name = $full"
            }
        }
    }
    $multi = $item.PSObject.Properties['MultiUser']
    if ($multi -and $multi.Value -eq 1) { $shared += "$regKey MultiUser = 1 (data goes to %APPDATA%\Envy)" }
}
if ($shared.Count -gt 0) {
    Write-Host 'Your registry makes a copy use these locations, which may be your personal data:' -ForegroundColor Yellow
    $shared | ForEach-Object { Write-Host "  $_" }
    Fail 'Not starting Envy. Use Windows Sandbox instead (New-KadSandboxConfig.ps1) or a separate Windows user account.'
}

Write-Host "Test folder : $testRoot"
Write-Host "Copy of the build in: $copy"
Write-Host 'Your installed Envy, HostCache.dat and the registry are not touched by this script.'
New-Item -ItemType Directory -Path $testRoot | Out-Null
Copy-Item -LiteralPath $BuildFolder -Destination $copy -Recurse

$proc = Start-Process -FilePath (Join-Path $copy 'Envy.exe') -WorkingDirectory $copy -PassThru
Write-Host "Envy started (PID $($proc.Id)). Leave it running for $Minutes minutes; do not start downloads."
$deadline = (Get-Date).AddMinutes($Minutes)
while ((Get-Date) -lt $deadline -and -not $proc.HasExited) { Start-Sleep -Seconds 10 }
if (-not $proc.HasExited) {
    [void]$proc.CloseMainWindow()
    if (-not $proc.WaitForExit(60000)) { Write-Host 'Envy did not close by itself; close it from its window.' -ForegroundColor Yellow }
}

$logs = Get-ChildItem -Path $testRoot -Filter 'Envy.log' -Recurse -ErrorAction SilentlyContinue
if (-not $logs) { Fail "Envy.log was not found under $testRoot. Check that DebugLog is on and the test ran." }
$log = $logs | Sort-Object LastWriteTime -Descending | Select-Object -First 1

$ipMap = @{}
function Mask-Ip([string]$ip) {
    if (-not $ipMap.ContainsKey($ip)) { $ipMap[$ip] = '<ip{0}>' -f ($ipMap.Count + 1) }
    return $ipMap[$ip]
}
$lines = Get-Content -LiteralPath $log.FullName -Encoding UTF8 | ForEach-Object {
    $l = $_
    $l = [regex]::Replace($l, '\b(\d{1,3}\.){3}\d{1,3}\b', { param($m) Mask-Ip $m.Value })
    $l = [regex]::Replace($l, '[A-Za-z]:\\[^\s"'']+', '<path>')
    $l = [regex]::Replace($l, '\b[0-9A-Fa-f]{32,64}\b', '<hex>')
    $l = [regex]::Replace($l, 'urn:[A-Za-z0-9:]+', 'urn:<hash>')
    $l = [regex]::Replace($l, '[\w.+-]+@[\w-]+\.[\w.-]+', '<email>')
    $l
}

$report = Join-Path $testRoot 'Envy-kad-report-anonymised.txt'
$kadLines = $lines | Where-Object { $_ -match 'Kad2|Kad nodes\.dat|Kad host cache|Kademlia' }
$status = $kadLines | Where-Object { $_ -match 'Kad2 status:' } | Select-Object -Last 1
$summary = @(
    "Envy Kad test report ($stamp)",
    "Minutes requested: $Minutes",
    "Log lines: $($lines.Count); Kad lines: $(@($kadLines).Count)",
    "Last status line: $status",
    '---- Kad lines (anonymised) ----'
)
($summary + $kadLines) | Set-Content -LiteralPath $report -Encoding UTF8
Write-Host "Report written: $report"
Write-Host 'Check it once, then send that file. It contains no IP addresses, paths, hashes or e-mails.'
