# Version Bump Script for Envy Project
# Interactive script for bumping versions locally

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("patch", "minor", "major", "prerelease", "final")]
    [string]$Type = "patch",

    [Parameter(Mandatory=$false)]
    [string]$PreReleaseLabel = "preview",

    [Parameter(Mandatory=$false)]
    [switch]$UpdateFiles,

    [Parameter(Mandatory=$false)]
    [switch]$Interactive
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$VersionScript = Join-Path $PSScriptRoot "auto-version.ps1"

# Ensure we're in the project root
Push-Location $ProjectRoot

try {
    if ($Interactive) {
        Write-Host "Envy Project Version Bump Tool" -ForegroundColor Green
        Write-Host "================================" -ForegroundColor Green
        Write-Host ""

        # Show current version
        if (Test-Path "version.json") {
            $currentVersion = Get-Content "version.json" | ConvertFrom-Json
            Write-Host "Current Version: $($currentVersion.displayVersion)" -ForegroundColor Cyan
            Write-Host "Full Version: $($currentVersion.fullVersion)" -ForegroundColor Cyan
            Write-Host ""
        }

        # Interactive menu
        Write-Host "Select version bump type:" -ForegroundColor Yellow
        Write-Host "1. Patch (bug fixes) - 1.2.3 → 1.2.4"
        Write-Host "2. Minor (new features) - 1.2.3 → 1.3.0"
        Write-Host "3. Major (breaking changes) - 1.2.3 → 2.0.0"
        Write-Host "4. Next pre-release - 1.2.3-preview.2 → 1.2.3-preview.3"
        Write-Host "5. Final - 1.2.3-preview.3 → 1.2.3"
        Write-Host ""

        $choice = Read-Host "Enter your choice (1-5)"
        switch ($choice) {
            "1" { $Type = "patch" }
            "2" { $Type = "minor" }
            "3" { $Type = "major" }
            "4" {
                $Type = "prerelease"
                $PreReleaseLabel = Read-Host "Enter pre-release label (default: preview)"
                if (-not $PreReleaseLabel) { $PreReleaseLabel = "preview" }
            }
            "5" { $Type = "final" }
            default {
                Write-Host "Invalid choice. Exiting." -ForegroundColor Red
                exit 1
            }
        }

        $updateFilesChoice = Read-Host "Update project files? (y/n, default: y)"
        if ($updateFilesChoice -eq "n" -or $updateFilesChoice -eq "N") {
            $UpdateFiles = $false
        } else {
            $UpdateFiles = $true
        }
    }

    # Build the argument list; splatting keeps the label from being parsed as code.
    $versionArguments = @{}
    switch ($Type) {
        "patch" { $versionArguments.IncrementPatch = $true }
        "minor" { $versionArguments.IncrementMinor = $true }
        "major" { $versionArguments.IncrementMajor = $true }
        "prerelease" {
            $versionArguments.PreRelease = $true
            $versionArguments.PreReleaseLabel = $PreReleaseLabel
        }
        "final" { $versionArguments.Final = $true }
    }

    if ($UpdateFiles) {
        $versionArguments.UpdateFiles = $true
    }

    $argumentSummary = ($versionArguments.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    Write-Host "Executing: $VersionScript ($argumentSummary)" -ForegroundColor Yellow
    Write-Host ""

    # Execute the command
    & $VersionScript @versionArguments

    # Show final version
    if (Test-Path "version.json") {
        $finalVersion = Get-Content "version.json" | ConvertFrom-Json
        Write-Host ""
        Write-Host "✓ Version successfully updated!" -ForegroundColor Green
        Write-Host "  New Version: $($finalVersion.displayVersion)" -ForegroundColor Cyan
        Write-Host "  Full Version: $($finalVersion.fullVersion)" -ForegroundColor Cyan
        Write-Host "  Build Number: $($finalVersion.build)" -ForegroundColor Cyan

        if ($Interactive) {
            Write-Host ""
            $commitChoice = Read-Host "Commit these changes? (y/n, default: n)"
            if ($commitChoice -eq "y" -or $commitChoice -eq "Y") {
                # Check git status
                $gitStatus = git status --porcelain
                if ($gitStatus) {
                    Write-Host "Committing version changes..." -ForegroundColor Yellow
                    git add .
                    $commitMessage = "release: bump version to $($finalVersion.displayVersion)"
                    git commit -m $commitMessage
                    Write-Host "✓ Changes committed!" -ForegroundColor Green

                    $pushChoice = Read-Host "Push to remote? (y/n, default: n)"
                    if ($pushChoice -eq "y" -or $pushChoice -eq "Y") {
                        git push
                        Write-Host "✓ Changes pushed to remote!" -ForegroundColor Green
                    }
                } else {
                    Write-Host "No changes to commit." -ForegroundColor Gray
                }
            }
        }
    }

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}

# Usage examples
if ($Interactive -and $MyInvocation.ScriptName -eq $MyInvocation.MyCommand.Path) {
    Write-Host ""
    Write-Host "Usage Examples:" -ForegroundColor Gray
    Write-Host "  .\bump-version.ps1 -Type patch -UpdateFiles" -ForegroundColor Gray
    Write-Host "  .\bump-version.ps1 -Interactive" -ForegroundColor Gray
    Write-Host "  .\bump-version.ps1 -Type prerelease -PreReleaseLabel rc" -ForegroundColor Gray
}
