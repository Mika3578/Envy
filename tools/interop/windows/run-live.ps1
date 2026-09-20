#Requires -Version 5.1
<#
.SYNOPSIS
  Windows operator helper for ENVY ↔ eMule/aMule live interop evidence (#160).

.DESCRIPTION
  Guides a reproducible local run without hard-coded Visual Studio paths.
  Does not download reference clients, does not install Wireshark, and never
  kills processes the harness did not start.

  Actual protocol PASS still requires packet/log evidence — see
  tools/interop/OPERATOR_CHECKLIST.md for manual GUI steps ENVY cannot automate.

.EXAMPLE
  .\tools\interop\windows\run-live.ps1 `
    -EnvyExe "D:\build\x64\Release\Envy.exe" `
    -EmuleExe "C:\Program Files\eMule\emule.exe" `
    -ReferenceVersion "0.70a" `
    -Scenarios current
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string] $EnvyExe = $env:ENVY_INTEROP_ENVY_EXE,

    [Parameter(Mandatory = $false)]
    [string] $EmuleExe = $env:ENVY_INTEROP_EMULE_EXE,

    [Parameter(Mandatory = $false)]
    [string] $AmuleExe = $env:ENVY_INTEROP_AMULE_EXE,

    [Parameter(Mandatory = $false)]
    [ValidateSet("emule-community", "amule", "amuled", "none")]
    [string] $ReferenceClient = "emule-community",

    [Parameter(Mandatory = $false)]
    [string] $ReferenceVersion = "",

    [Parameter(Mandatory = $false)]
    [string] $WorkDir = "",

    [Parameter(Mandatory = $false)]
    [string] $ArtifactDir = "",

    [Parameter(Mandatory = $false)]
    [string] $Scenarios = "current",

    [Parameter(Mandatory = $false)]
    [switch] $EnablePcap,

    [Parameter(Mandatory = $false)]
    [int] $PcapDurationSec = 0,

    [Parameter(Mandatory = $false)]
    [switch] $AllowExternalNetwork,

    [Parameter(Mandatory = $false)]
    [switch] $DryRun,

    [Parameter(Mandatory = $false)]
    [string] $PacketEvidence = "",

    [Parameter(Mandatory = $false)]
    [string] $Python = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    # tools/interop/windows -> repository root
    return (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
}

function Assert-Exe([string] $Path, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label path is empty. Pass -$Label or set ENVY_INTEROP_*."
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label does not exist as a file: $Path"
    }
}

$RepoRoot = Resolve-RepoRoot
$RunPy = Join-Path $RepoRoot "tools\interop\run.py"
if (-not (Test-Path -LiteralPath $RunPy)) {
    throw "Cannot find tools/interop/run.py under $RepoRoot"
}

Write-Host "ENVY interop Windows helper (#160)"
Write-Host "Repo: $RepoRoot"
Write-Host ""
Write-Host "This helper prepares an isolated run. It does NOT claim ED2K/Kad interoperability."
Write-Host "Read tools/interop/OPERATOR_CHECKLIST.md for required manual GUI clicks."
Write-Host ""

if (-not $DryRun) {
    Assert-Exe $EnvyExe "EnvyExe"
    if ($ReferenceClient -eq "emule-community") {
        Assert-Exe $EmuleExe "EmuleExe"
    }
    elseif ($ReferenceClient -in @("amule", "amuled")) {
        Assert-Exe $AmuleExe "AmuleExe"
    }
    if ([string]::IsNullOrWhiteSpace($ReferenceVersion)) {
        Write-Warning "ReferenceVersion is empty — record the exact client version in the report."
    }
}

# Detect whether a harness-owned marker from a prior crash exists (informational).
$DefaultWork = if ($WorkDir) { $WorkDir } else { Join-Path $RepoRoot "tools\interop\artifacts\windows-work" }
$DefaultArt = if ($ArtifactDir) { $ArtifactDir } else { Join-Path $RepoRoot "tools\interop\artifacts" }
New-Item -ItemType Directory -Force -Path $DefaultWork | Out-Null
New-Item -ItemType Directory -Force -Path $DefaultArt | Out-Null

$argsList = @(
    $RunPy
)
if ($DryRun) {
    $argsList += "--dry-run"
}
else {
    $argsList += "--live"
    $argsList += @("--envy-exe", $EnvyExe)
    if ($EmuleExe) { $argsList += @("--emule-exe", $EmuleExe) }
    if ($AmuleExe) { $argsList += @("--amule-exe", $AmuleExe) }
}
$argsList += @("--reference-client", $ReferenceClient)
if ($ReferenceVersion) { $argsList += @("--reference-version", $ReferenceVersion) }
$argsList += @("--work-dir", $DefaultWork)
$argsList += @("--artifact-dir", $DefaultArt)
$argsList += @("--scenarios", $Scenarios)
if ($EnablePcap) { $argsList += "--enable-pcap" }
if ($PcapDurationSec -gt 0) { $argsList += @("--pcap-duration-sec", "$PcapDurationSec") }
if ($AllowExternalNetwork) { $argsList += "--allow-external-network" }
if ($PacketEvidence) { $argsList += @("--packet-evidence", $PacketEvidence) }

Write-Host "Launching:"
Write-Host ("  {0} {1}" -f $Python, ($argsList -join " "))
Write-Host ""
Write-Host "Owned processes only. The harness never kills an existing user Envy/eMule."
Write-Host "If Global\Envy or eMule single-instance mutex is held, close THAT instance yourself."
Write-Host ""

& $Python @argsList
$exit = $LASTEXITCODE
Write-Host ""
Write-Host "Exit code: $exit"
Write-Host "Sanitize and attach run-summary.md / sanitized logs to issue #160."
Write-Host "Raw pcaps stay local (gitignored)."
exit $exit
