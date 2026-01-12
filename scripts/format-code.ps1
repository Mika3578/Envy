# PowerShell script to format code using clang-format
# Usage: .\scripts\format-code.ps1 [-CheckOnly]

param(
    [switch]$CheckOnly = $false
)

$ErrorActionPreference = "Stop"

# Find clang-format
$clangFormat = "clang-format"

if (-not (Get-Command $clangFormat -ErrorAction SilentlyContinue)) {
    Write-Host "clang-format not found. Installing..." -ForegroundColor Yellow

    # Try to find in common locations
    $possiblePaths = @(
        "C:\Program Files\LLVM\bin\clang-format.exe",
        "C:\Program Files (x86)\LLVM\bin\clang-format.exe",
        "$env:LOCALAPPDATA\Programs\LLVM\bin\clang-format.exe"
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $clangFormat = $path
            break
        }
    }

    if (-not (Test-Path $clangFormat)) {
        Write-Host "ERROR: clang-format not found. Please install LLVM tools." -ForegroundColor Red
        Write-Host "Download from: https://llvm.org/builds/" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host "Using: $clangFormat" -ForegroundColor Green
Write-Host ""

# Get all C++ files
$files = Get-ChildItem -Path . -Include *.cpp,*.h,*.hpp -Recurse |
    Where-Object {
        $_.FullName -notmatch "\\Examples\\" -and
        $_.FullName -notmatch "\\build\\" -and
        $_.FullName -notmatch "\\bin\\" -and
        $_.FullName -notmatch "\\.git\\"
    }

Write-Host "Found $($files.Count) C++ files to check" -ForegroundColor Cyan
Write-Host ""

$formattedCount = 0
$needsFormatting = @()

foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($PWD.Path.Length + 1)

    if ($CheckOnly) {
        # Check if file needs formatting
        $tempFile = [System.IO.Path]::GetTempFileName()
        & $clangFormat -style=file $file.FullName | Out-File -FilePath $tempFile -Encoding utf8

        $original = Get-Content $file.FullName -Raw
        $formatted = Get-Content $tempFile -Raw

        Remove-Item $tempFile

        if ($original -ne $formatted) {
            $needsFormatting += $relativePath
            Write-Host "Needs formatting: $relativePath" -ForegroundColor Yellow
        } else {
            Write-Host "OK: $relativePath" -ForegroundColor Gray
        }
    } else {
        # Format the file
        Write-Host "Formatting: $relativePath" -ForegroundColor Cyan
        & $clangFormat -style=file -i $file.FullName
        $formattedCount++
    }
}

Write-Host ""

if ($CheckOnly) {
    if ($needsFormatting.Count -gt 0) {
        Write-Host "$($needsFormatting.Count) file(s) need formatting" -ForegroundColor Red
        Write-Host ""
        Write-Host "Run without -CheckOnly to format:" -ForegroundColor Yellow
        Write-Host "  .\scripts\format-code.ps1" -ForegroundColor White
        exit 1
    } else {
        Write-Host "All files are properly formatted!" -ForegroundColor Green
        exit 0
    }
} else {
    Write-Host "Formatted $formattedCount file(s)" -ForegroundColor Green
}
