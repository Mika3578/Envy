# PowerShell script to run static analysis tools
# Usage: .\scripts\run-static-analysis.ps1

$ErrorActionPreference = "Stop"

Write-Host "Envy Static Analysis" -ForegroundColor Green
Write-Host "====================" -ForegroundColor Green
Write-Host ""

# Check for CppCheck
$cppcheck = "cppcheck"

if (-not (Get-Command $cppcheck -ErrorAction SilentlyContinue)) {
    Write-Host "CppCheck not found. Install from: https://cppcheck.sourceforge.io/" -ForegroundColor Yellow
    Write-Host "Or download portable version and add to PATH" -ForegroundColor Yellow
    exit 1
}

Write-Host "Running CppCheck..." -ForegroundColor Cyan
Write-Host ""

$reportDir = ".\reports"
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir | Out-Null
}

$reportFile = "$reportDir\cppcheck-report.xml"
$outputFile = "$reportDir\cppcheck-output.txt"

& $cppcheck `
    --enable=all `
    --suppress=missingIncludeSystem `
    --suppress=unusedFunction `
    --suppress-list=.cppcheck-suppressions `
    --xml --xml-version=2 `
    --output-file=$reportFile `
    --inline-suppr `
    --force `
    --platform=win64 `
    Envy\ Services\ HashLib\ Plugins\ `
    --exclude=Examples\ `
    2>&1 | Tee-Object -FilePath $outputFile

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Static analysis completed successfully!" -ForegroundColor Green
    Write-Host "Report saved to: $reportFile" -ForegroundColor Cyan
    Write-Host "Output saved to: $outputFile" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "Static analysis found issues. Review the report:" -ForegroundColor Yellow
    Write-Host "  $reportFile" -ForegroundColor White
    Write-Host "  $outputFile" -ForegroundColor White
}
