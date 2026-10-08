#Requires -Version 5.1
<#
.SYNOPSIS
    Bootstrap and verify a Windows development environment for Envy.

.PARAMETER Check
    Report prerequisites and repository-owned policy only; do not generate files.

.PARAMETER GenerateCompileCommands
    After a successful MSVC build, write gitignored compile_commands.json at repo root.

.PARAMETER Configuration
    Passed to generate-compile-commands.ps1 (default Release|x64).
#>
param(
    [switch]$Check,
    [switch]$GenerateCompileCommands,
    [string]$Configuration = 'Release|x64'
)

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
$repoRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path

function Write-Section([string]$Title)
{
    Write-Host ""
    Write-Host "=== $Title ==="
}

function Test-CommandOnPath([string]$Name)
{
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

$issues = @()

Write-Section 'Repository'
Write-Host "Root: $repoRoot"
foreach ($rel in @(
        'AGENTS.md',
        '.editorconfig',
        '.gitattributes',
        'Visual Studio\Envy.sln',
        'vcpkg.json',
        'docs\10_dev\development-environment.md'
    ))
{
    $path = Join-Path $repoRoot $rel
    if (Test-Path -LiteralPath $path)
    {
        Write-Host "  OK   $rel"
    }
    else
    {
        Write-Host "  MISS $rel"
        $issues += "Missing $rel"
    }
}

Write-Section 'Visual Studio / MSBuild'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswhere)
{
    # Envy requires v145 tools plus optional MFC/ATL components (StdAfx.h).
    $installPath = & $vswhere -latest -prerelease -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -requires Microsoft.VisualStudio.Component.VC.v145.x86.x64 `
        -requires Microsoft.VisualStudio.Component.VC.ATL `
        -requires Microsoft.VisualStudio.Component.VC.ATLMFC `
        -property installationPath 2>$null | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace($installPath))
    {
        $displayName = & $vswhere -latest -prerelease -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -requires Microsoft.VisualStudio.Component.VC.v145.x86.x64 `
            -requires Microsoft.VisualStudio.Component.VC.ATL `
            -requires Microsoft.VisualStudio.Component.VC.ATLMFC `
            -property displayName 2>$null | Select-Object -First 1
        $installVersion = & $vswhere -latest -prerelease -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -requires Microsoft.VisualStudio.Component.VC.v145.x86.x64 `
            -requires Microsoft.VisualStudio.Component.VC.ATL `
            -requires Microsoft.VisualStudio.Component.VC.ATLMFC `
            -property installationVersion 2>$null | Select-Object -First 1
        Write-Host "  OK   $displayName $installVersion (v145 + ATL/MFC)"
        Write-Host "       $installPath"
    }
    else
    {
        $v145Path = & $vswhere -latest -prerelease -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -requires Microsoft.VisualStudio.Component.VC.v145.x86.x64 `
            -property installationPath 2>$null | Select-Object -First 1
        if (-not [string]::IsNullOrWhiteSpace($v145Path))
        {
            $hasAtl = -not [string]::IsNullOrWhiteSpace((& $vswhere -latest -prerelease -products * `
                    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                    -requires Microsoft.VisualStudio.Component.VC.v145.x86.x64 `
                    -requires Microsoft.VisualStudio.Component.VC.ATL `
                    -property installationPath 2>$null | Select-Object -First 1))
            $hasMfc = -not [string]::IsNullOrWhiteSpace((& $vswhere -latest -prerelease -products * `
                    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                    -requires Microsoft.VisualStudio.Component.VC.v145.x86.x64 `
                    -requires Microsoft.VisualStudio.Component.VC.ATLMFC `
                    -property installationPath 2>$null | Select-Object -First 1))
            $missing = @()
            if (-not $hasAtl) { $missing += 'ATL' }
            if (-not $hasMfc) { $missing += 'MFC' }
            Write-Host ("  MISS Visual Studio C++ {0} for v145 (vswhere)" -f ($missing -join '/'))
            $issues += ('Install C++ {0} for the latest MSVC/v145 toolset via Visual Studio Installer (Desktop development with C++ -> ATL/MFC).' -f ($missing -join ' and '))
        }
        else
        {
            # Distinguish missing VS vs missing v145 when ATL/MFC is not the blocker.
            $anyVc = & $vswhere -latest -prerelease -products * `
                -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                -property installationPath 2>$null | Select-Object -First 1
            if (-not [string]::IsNullOrWhiteSpace($anyVc))
            {
                Write-Host '  MISS Visual Studio C++ toolset v145 (vswhere)'
                $issues += 'Install the MSVC v145 (VS 2026) x86/x64 build tools component.'
            }
            else
            {
                Write-Host '  MISS Visual Studio with VC++ tools (vswhere)'
                $issues += 'Install Visual Studio 2026 with Desktop development with C++ (toolset v145, ATL, and MFC).'
            }
        }
    }
}
else
{
    Write-Host "  MISS vswhere.exe"
    $issues += 'Install Visual Studio 2026.'
}

if (Test-CommandOnPath 'msbuild')
{
    Write-Host "  OK   msbuild on PATH"
}
else
{
    Write-Host '  WARN msbuild not on PATH (open Developer PowerShell or VS Installer)'
}


Write-Section 'Windows SDK'
$sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
$sdkOk = $false
if (Test-Path -LiteralPath $sdkRoot)
{
    $sdkDirs = @(Get-ChildItem -LiteralPath $sdkRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^10\.' } |
        Sort-Object { [version]($_.Name -replace '[^\d.].*$','') } -Descending)
    if ($sdkDirs.Count -gt 0)
    {
        $sdkOk = $true
        Write-Host "  OK   Windows 10/11 SDK $($sdkDirs[0].Name)"
    }
}
if (-not $sdkOk)
{
    Write-Host '  MISS Windows 10/11 SDK (Windows Kits\10)'
    $issues += 'Install a Windows 10/11 SDK (WindowsTargetPlatformVersion=10.0) via Visual Studio Installer.'
}

Write-Section 'vcpkg manifest'
$bootstrap = Join-Path $repoRoot 'scripts\bootstrap-vcpkg.cmd'
if (Test-Path -LiteralPath $bootstrap)
{
    Write-Host '  Win32: scripts\bootstrap-vcpkg.cmd -Triplet x86-windows-static'
    Write-Host '  x64 manifest (optional): scripts\bootstrap-vcpkg.cmd'
    Write-Host '  Both: scripts\bootstrap-vcpkg.cmd -All'
    Write-Host '  See docs\10_dev\build.md (x64 BugSplat does not require vcpkg_installed\x64-windows-static).'
}
else
{
    $issues += 'scripts\bootstrap-vcpkg.cmd missing'
}

Write-Section 'Optional: clangd (Cursor / VS Code navigation)'
if (Test-CommandOnPath 'clangd')
{
    $ver = & clangd --version 2>$null | Select-Object -First 1
    Write-Host "  OK   $ver"
}
else
{
    Write-Host '  INFO clangd not on PATH; install via llvm-vs-code-extensions.vscode-clangd or LLVM.'
    Write-Host '       See docs/10_dev/development-environment.md'
}

Write-Section 'Generated / local (must not be committed)'
foreach ($rel in @('compile_commands.json', '.vs', 'vcpkg_installed'))
{
    $path = Join-Path $repoRoot $rel
    $present = Test-Path -LiteralPath $path
    Write-Host ("  {0,-4} {1}" -f ($(if ($present) { 'yes' } else { 'no ' })), $rel)
}

if ($GenerateCompileCommands -and -not $Check)
{
    Write-Section 'compile_commands.json'
    $gen = Join-Path $scriptDir 'generate-compile-commands.ps1'
    try
    {
        & $gen -Configuration $Configuration
    }
    catch
    {
        Write-Host "  WARN generate-compile-commands.ps1 failed: $($_.Exception.Message)"
        $issues += 'compile_commands.json was not generated (build in VS first, then re-run with -GenerateCompileCommands).'
    }
}

Write-Section 'Encoding (#350)'
Write-Host '  Legacy C/C++ headers may use non-UTF-8 bytes. Do not force UTF-8 on save.'
Write-Host '  CI blocks NEW U+FFFD (EF BF BD) in changed first-party sources.'

Write-Section 'Summary'
if ($issues.Count -eq 0)
{
    Write-Host 'Environment check: no blocking issues reported.'
    exit 0
}

foreach ($i in $issues) { Write-Host "  - $i" }
Write-Host 'Environment check: action required (see messages above).'
exit 1
