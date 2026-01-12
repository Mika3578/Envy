# PowerShell script to verify build with Visual Studio 2026
# Usage: .\scripts\verify-build.ps1 [-Configuration <Debug|Release>] [-Platform <Win32|x64>]

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Debug", "Release", "All")]
    [string]$Configuration = "All",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Win32", "x64", "All")]
    [string]$Platform = "All",

    [switch]$Clean = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

Write-Host "Envy Build Verification Script" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green
Write-Host ""

# Find MSBuild
$msbuild = & "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest `
    -products * `
    -requires Microsoft.Component.MSBuild `
    -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1

if (-not $msbuild -or -not (Test-Path $msbuild)) {
    $msbuild = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $msbuild) {
        $msbuild = & $msbuild `
            -latest `
            -products * `
            -requires Microsoft.Component.MSBuild `
            -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
    }
}

if (-not $msbuild -or -not (Test-Path $msbuild)) {
    Write-Host "ERROR: MSBuild not found. Please install Visual Studio 2026." -ForegroundColor Red
    exit 1
}

Write-Host "Using MSBuild: $msbuild" -ForegroundColor Cyan
Write-Host ""

$solutionPath = "Visual Studio\Envy.sln"
if (-not (Test-Path $solutionPath)) {
    Write-Host "ERROR: Solution file not found: $solutionPath" -ForegroundColor Red
    exit 1
}

# Build configurations
$configs = @()
if ($Configuration -eq "All") {
    $configs = @("Debug", "Release")
} else {
    $configs = @($Configuration)
}

# Platforms
$platforms = @()
if ($Platform -eq "All") {
    $platforms = @("Win32", "x64")
} else {
    $platforms = @($Platform)
}

$buildResults = @()
$failedBuilds = @()

foreach ($config in $configs) {
    foreach ($plat in $platforms) {
        Write-Host ""
        Write-Host "Building: $config | $plat" -ForegroundColor Yellow
        Write-Host "------------------------" -ForegroundColor Yellow

        # Clean if requested
        if ($Clean) {
            Write-Host "Cleaning..." -ForegroundColor Gray
            & $msbuild $solutionPath `
                /t:Clean `
                /p:Configuration=$config `
                /p:Platform=$plat `
                /p:PlatformToolset=v145 `
                /m `
                /v:minimal | Out-Null

            if ($LASTEXITCODE -ne 0) {
                Write-Host "  Clean failed!" -ForegroundColor Red
                $failedBuilds += "Clean $config $plat"
                continue
            }
        }

        # Build
        Write-Host "Building..." -ForegroundColor Cyan
        $logFile = ".\reports\build-$config-$plat.log"
        $logDir = Split-Path $logFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir | Out-Null
        }

        $verbosity = if ($Verbose) { "detailed" } else { "minimal" }

        & $msbuild $solutionPath `
            /t:Rebuild `
            /p:Configuration=$config `
            /p:Platform=$plat `
            /p:PlatformToolset=v145 `
            /m `
            /v:$verbosity `
            2>&1 | Tee-Object -FilePath $logFile

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Build succeeded!" -ForegroundColor Green
            $buildResults += @{
                Configuration = $config
                Platform = $plat
                Status = "Success"
                LogFile = $logFile
            }
        } else {
            Write-Host "  ✗ Build failed!" -ForegroundColor Red
            $buildResults += @{
                Configuration = $config
                Platform = $plat
                Status = "Failed"
                LogFile = $logFile
            }
            $failedBuilds += "$config $plat"
        }
    }
}

# Summary
Write-Host ""
Write-Host "Build Verification Summary" -ForegroundColor Green
Write-Host "=========================" -ForegroundColor Green
Write-Host ""

foreach ($result in $buildResults) {
    $statusColor = if ($result.Status -eq "Success") { "Green" } else { "Red" }
    Write-Host "$($result.Configuration) | $($result.Platform): $($result.Status)" -ForegroundColor $statusColor
    if ($result.Status -eq "Failed") {
        Write-Host "  Log: $($result.LogFile)" -ForegroundColor Gray
    }
}

Write-Host ""

if ($failedBuilds.Count -gt 0) {
    Write-Host "Failed builds: $($failedBuilds.Count)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Review log files in .\reports\ for details" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "All builds succeeded! ✓" -ForegroundColor Green
    exit 0
}
