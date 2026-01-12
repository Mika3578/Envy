# PowerShell script to update dependencies for Envy project
# Usage: .\scripts\update-dependencies.ps1 [-Dependency <name>] [-DryRun]

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("SQLite", "zlib", "bzip2", "MiniUPnP", "All")]
    [string]$Dependency = "All",

    [switch]$DryRun = $false
)

Write-Host "Envy Dependency Update Script" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green
Write-Host ""

if ($DryRun) {
    Write-Host "DRY RUN MODE - No files will be modified" -ForegroundColor Yellow
    Write-Host ""
}

function Update-SQLite {
    Write-Host "Updating SQLite..." -ForegroundColor Cyan
    Write-Host "  Current: Check Services\SQLite\sqlite3.h for version" -ForegroundColor Gray
    Write-Host "  Target:  SQLite 3.45.x+ (latest stable)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Steps:" -ForegroundColor Yellow
    Write-Host "  1. Download latest SQLite amalgamation from https://www.sqlite.org/download.html"
    Write-Host "  2. Extract sqlite3.c and sqlite3.h to Services\SQLite\"
    Write-Host "  3. Update project file references if needed"
    Write-Host "  4. Test database compatibility"
    Write-Host "  5. Verify SQL queries work with new version"
    Write-Host ""

    if (-not $DryRun) {
        Write-Host "  Manual update required. See NEXT_STEPS.md for detailed instructions." -ForegroundColor Yellow
    }
}

function Update-Zlib {
    Write-Host "Updating zlib..." -ForegroundColor Cyan
    Write-Host "  Current: Check Services\zlib\zlib.h for version" -ForegroundColor Gray
    Write-Host "  Target:  zlib 1.3.x (latest stable)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Steps:" -ForegroundColor Yellow
    Write-Host "  1. Download latest zlib from https://www.zlib.net/"
    Write-Host "  2. Extract source to Services\zlib\"
    Write-Host "  3. Update project file source lists"
    Write-Host "  4. Test compression/decompression"
    Write-Host "  5. Verify API compatibility"
    Write-Host ""

    if (-not $DryRun) {
        Write-Host "  Manual update required. See NEXT_STEPS.md for detailed instructions." -ForegroundColor Yellow
    }
}

function Update-Bzip2 {
    Write-Host "Updating bzip2..." -ForegroundColor Cyan
    Write-Host "  Current: Check Services\Bzlib\ for version" -ForegroundColor Gray
    Write-Host "  Target:  Latest bzip2 version" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Steps:" -ForegroundColor Yellow
    Write-Host "  1. Download latest bzip2 from https://www.sourceware.org/bzip2/"
    Write-Host "  2. Extract source to Services\Bzlib\"
    Write-Host "  3. Update project files"
    Write-Host "  4. Test archive compatibility"
    Write-Host ""

    if (-not $DryRun) {
        Write-Host "  Manual update required. See NEXT_STEPS.md for detailed instructions." -ForegroundColor Yellow
    }
}

function Update-MiniUPnP {
    Write-Host "Updating MiniUPnP..." -ForegroundColor Cyan
    Write-Host "  Current: Check Services\MiniUPnP\ for version" -ForegroundColor Gray
    Write-Host "  Target:  Latest MiniUPnP version" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Steps:" -ForegroundColor Yellow
    Write-Host "  1. Download latest MiniUPnP from https://miniupnp.tuxfamily.org/"
    Write-Host "  2. Extract source to Services\MiniUPnP\"
    Write-Host "  3. Update project files"
    Write-Host "  4. Test UPnP functionality"
    Write-Host "  5. Verify port forwarding works"
    Write-Host ""

    if (-not $DryRun) {
        Write-Host "  Manual update required. See NEXT_STEPS.md for detailed instructions." -ForegroundColor Yellow
    }
}

# Main execution
switch ($Dependency) {
    "SQLite" { Update-SQLite }
    "zlib" { Update-Zlib }
    "bzip2" { Update-Bzip2 }
    "MiniUPnP" { Update-MiniUPnP }
    "All" {
        Update-SQLite
        Update-Zlib
        Update-Bzip2
        Update-MiniUPnP
    }
}

Write-Host ""
Write-Host "Dependency update check complete!" -ForegroundColor Green
Write-Host "For detailed instructions, see: NEXT_STEPS.md" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Test all functionality after updating dependencies!" -ForegroundColor Yellow
