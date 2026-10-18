#Requires -Version 5.1
<#
.SYNOPSIS
    Launch the locally built Envy.exe for the chosen Configuration|Platform.

.DESCRIPTION
    Starts Envy\<Configuration> <Platform>\Envy.exe (the MSBuild output of the
    Envy project). It does not build; run "Envy: Build Project" (Envy) first. Builds\*.exe
    are Inno Setup installer packages, not the application, and are not started.
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('x64', 'Win32')]
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$exe = Join-Path $repoRoot "Envy\$Configuration $Platform\Envy.exe"
if (-not (Test-Path -LiteralPath $exe))
{
    throw "Envy.exe not found for $Configuration|$Platform. Run 'Envy: Build Project' (Envy) first: $exe"
}

Write-Host "Starting: $exe"
Start-Process -FilePath $exe -WorkingDirectory (Split-Path -Parent $exe)
