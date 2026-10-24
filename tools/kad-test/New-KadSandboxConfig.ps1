<#
.SYNOPSIS
  Creates a Windows Sandbox file (.wsb) that runs a CI build of Envy in a throw-away Windows.

.DESCRIPTION
  Needs Windows 10/11 Pro, Enterprise or Education with the "Windows Sandbox" feature on.
  The sandbox starts with an empty registry and an empty profile, and everything is deleted
  when its window is closed, so your installed Envy and its data cannot be affected.
  The build folder is mapped read-only; only the 'out' folder is writable.

  Inside the sandbox Envy runs twice: a first run of -Minutes, a normal close (which saves
  HostCache.dat), then a restart of -RestartMinutes to check that the saved state is usable.
  The QuickStart wizard is skipped (Settings\FirstRun = 0 in the sandbox registry) so that
  Envy connects on its own (Connection.AutoConnect is on by default).

.PARAMETER BuildFolder
  Folder that contains Envy.exe and its Data folder (artifacts\portable of the CI artifact).
.PARAMETER HostCacheFile
  Optional. A HostCache.dat saved by an earlier build, to check the one-time removal of its
  byte-reversed Kad entries. The file is copied; the original is not modified.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BuildFolder,
    [string]$WorkFolder = (Join-Path $env:USERPROFILE 'EnvyKadSandbox'),
    [ValidateRange(3, 60)][int]$Minutes = 10,
    [ValidateRange(1, 30)][int]$RestartMinutes = 3,
    [string]$HostCacheFile = ''
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath (Join-Path $BuildFolder 'Envy.exe'))) { throw "Envy.exe not found in '$BuildFolder'." }
if (-not (Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue)) {
    throw 'Windows Sandbox is not installed (Windows Home does not have it). Use another Windows user account instead.'
}
$BuildFolder = (Resolve-Path -LiteralPath $BuildFolder).Path
$out = Join-Path $WorkFolder 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
Remove-Item -LiteralPath (Join-Path $out 'done.txt') -ErrorAction SilentlyContinue
$cacheCopy = Join-Path $out 'HostCache.input.dat'
Remove-Item -LiteralPath $cacheCopy -ErrorAction SilentlyContinue
if ($HostCacheFile) {
    if (-not (Test-Path -LiteralPath $HostCacheFile)) { throw "HostCache file not found: '$HostCacheFile'." }
    Copy-Item -LiteralPath $HostCacheFile -Destination $cacheCopy
}

$inner = @'
$ErrorActionPreference = 'Continue'
$desk = 'C:\Users\WDAGUtilityAccount\Desktop'
$dst = 'C:\EnvyTest'
$summary = "$desk\out\summary.txt"
Copy-Item -Recurse -Force "$desk\build" $dst
# This registry is the sandbox's own and is discarded with it.
$k = 'HKCU:\Software\Envy\Envy'
New-Item -Path "$k\Settings" -Force | Out-Null
New-ItemProperty -Path $k -Name 'DebugLog' -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $k -Name 'LogLevel' -Value 4 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "$k\Settings" -Name 'FirstRun' -Value 0 -PropertyType DWord -Force | Out-Null
if (Test-Path "$desk\out\HostCache.input.dat") {
    Copy-Item -Force "$desk\out\HostCache.input.dat" "$dst\Data\HostCache.dat"
    'HostCache.dat from an earlier build was placed in Data before the first run.' | Add-Content $summary
}
function Get-ArchiveVersion {
    $f = "$dst\Data\HostCache.dat"
    if (-not (Test-Path $f)) { return 'missing' }
    $b = [System.IO.File]::ReadAllBytes($f)
    if ($b.Length -lt 4) { return 'too short' }
    return [System.BitConverter]::ToInt32($b, 0)
}
function Invoke-EnvyRun([int]$Seconds, [string]$Name) {
    $p = Start-Process -FilePath "$dst\Envy.exe" -ArgumentList '-nowarn' -WorkingDirectory $dst -PassThru
    Start-Sleep -Seconds $Seconds
    [void]$p.CloseMainWindow()
    if (-not $p.WaitForExit(120000)) {
        "${Name}: Envy did not exit within 2 minutes after the close request." | Add-Content $summary
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    "${Name}: HostCache.dat archive version after exit = $(Get-ArchiveVersion)" | Add-Content $summary
    Copy-Item -Force "$dst\Data\Envy.log" "$desk\out\Envy-after-$Name.log" -ErrorAction SilentlyContinue
}
"HostCache.dat archive version before the first run = $(Get-ArchiveVersion)" | Add-Content $summary
Invoke-EnvyRun (__MINUTES__ * 60) 'run1'
Invoke-EnvyRun (__RESTART__ * 60) 'run2'
'done' | Set-Content "$desk\out\done.txt"
'@
$inner = $inner.Replace('__MINUTES__', [string]$Minutes).Replace('__RESTART__', [string]$RestartMinutes)
Set-Content -LiteralPath (Join-Path $out 'sandbox-run.ps1') -Value $inner -Encoding UTF8
Remove-Item -LiteralPath (Join-Path $out 'summary.txt') -ErrorAction SilentlyContinue

$wsb = @"
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder><HostFolder>$BuildFolder</HostFolder><SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\build</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$out</HostFolder><SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\out</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\out\sandbox-run.ps1</Command></LogonCommand>
</Configuration>
"@
$file = Join-Path $WorkFolder 'EnvyKadTest.wsb'
Set-Content -LiteralPath $file -Value $wsb -Encoding UTF8
$total = $Minutes + $RestartMinutes + 3
Write-Host "Created $file"
Write-Host "Double-click it. Wait about $total minutes; out\done.txt then appears."
Write-Host 'out\summary.txt, out\Envy-after-run1.log and out\Envy-after-run2.log are the results.'
Write-Host 'Run Anonymise-KadLog.ps1 on Envy-after-run2.log before sending it (it hides IPs, paths, hashes and e-mails).'
