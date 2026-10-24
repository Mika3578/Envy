<#
.SYNOPSIS
  Creates a Windows Sandbox file (.wsb) that runs a CI build of Envy in a throw-away Windows.

.DESCRIPTION
  Needs Windows 10/11 Pro, Enterprise or Education with the "Windows Sandbox" feature on.
  The sandbox starts with an empty registry and an empty profile, and everything is deleted
  when its window is closed, so your installed Envy and its data cannot be affected.
  The build folder is mapped read-only; only the 'out' folder is writable.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BuildFolder,
    [string]$WorkFolder = (Join-Path $env:USERPROFILE 'EnvyKadSandbox')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath (Join-Path $BuildFolder 'Envy.exe'))) { throw "Envy.exe not found in '$BuildFolder'." }
if (-not (Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue)) {
    throw 'Windows Sandbox is not installed (Windows Home does not have it). Use another Windows user account instead.'
}
$out = Join-Path $WorkFolder 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$inner = @'
$ErrorActionPreference = 'Continue'
$dst = 'C:\EnvyTest'
Copy-Item -Recurse -Force 'C:\Users\WDAGUtilityAccount\Desktop\build' $dst
# Debug logging for the test (this registry is the sandbox's own and is discarded).
$k = 'HKCU:\Software\Envy\Envy'
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name 'DebugLog' -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $k -Name 'LogLevel' -Value 4 -PropertyType DWord -Force | Out-Null
$p = Start-Process -FilePath "$dst\Envy.exe" -WorkingDirectory $dst -PassThru
Start-Sleep -Seconds 600
Copy-Item -Force "$dst\Data\Envy.log" 'C:\Users\WDAGUtilityAccount\Desktop\out\Envy.log' -ErrorAction SilentlyContinue
'done' | Set-Content 'C:\Users\WDAGUtilityAccount\Desktop\out\done.txt'
'@
Set-Content -LiteralPath (Join-Path $out 'sandbox-run.ps1') -Value $inner -Encoding UTF8

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
Write-Host "Created $file"
Write-Host 'Double-click it. Wait about 11 minutes; out\done.txt then appears. Envy.log is in the out folder.'
Write-Host 'Then run Anonymise-KadLog.ps1 on that Envy.log (it hides IPs, paths, hashes and e-mails).'
