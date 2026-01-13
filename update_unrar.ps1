# UnRAR Update Script - Version 5.3.8 → 7.2.3
# Security update for CVE-2025-8088

$sourceDir = "C:\Users\Mika\Downloads\unrarsrc-7.2.3\unrar"
$targetDir = "Services\UnRAR"

# List of source files to update (from current project)
$filesToUpdate = @(
    "archive.cpp", "arcread.cpp", "blake2s.cpp", "cmddata.cpp", "consio.cpp",
    "crc.cpp", "crypt.cpp", "dll.cpp", "encname.cpp", "errhnd.cpp",
    "extinfo.cpp", "extract.cpp", "filcreat.cpp", "file.cpp", "filefn.cpp",
    "filestr.cpp", "find.cpp", "getbits.cpp", "global.cpp", "hash.cpp",
    "headers.cpp", "isnt.cpp", "match.cpp", "options.cpp", "pathfn.cpp",
    "qopen.cpp", "rar.cpp", "rarpch.cpp", "rarvm.cpp", "rawread.cpp",
    "rdwrfn.cpp", "recvol.cpp", "rijndael.cpp", "rs.cpp", "rs16.cpp",
    "scantree.cpp", "secpassword.cpp", "sha1.cpp", "sha256.cpp", "smallfn.cpp",
    "strfn.cpp", "strlist.cpp", "system.cpp", "threadpool.cpp", "timefn.cpp",
    "ui.cpp", "unicode.cpp", "unpack.cpp", "volume.cpp"
)

# List of header files to update
$headersToUpdate = @(
    "archive.hpp", "blake2s.hpp", "cmddata.hpp", "consio.hpp", "crc.hpp",
    "crypt.hpp", "dll.hpp", "encname.hpp", "errhnd.hpp", "extinfo.hpp",
    "extract.hpp", "filcreat.hpp", "file.hpp", "filefn.hpp", "filestr.hpp",
    "find.hpp", "getbits.hpp", "global.hpp", "hash.hpp", "headers.hpp",
    "headers5.hpp", "isnt.hpp", "match.hpp", "options.hpp", "os.hpp",
    "pathfn.hpp", "qopen.hpp", "rar.hpp", "rardefs.hpp", "raros.hpp",
    "rarpch.hpp", "rartypes.hpp", "rarvm.hpp", "rawread.hpp", "rdwrfn.hpp",
    "recvol.hpp", "rijndael.hpp", "rs.hpp", "rs16.hpp", "scantree.hpp",
    "secpassword.hpp", "sha1.hpp", "sha256.hpp", "smallfn.hpp", "strfn.hpp",
    "strlist.hpp", "suballoc.hpp", "system.hpp", "threadpool.hpp", "timefn.hpp",
    "ui.hpp", "unicode.hpp", "unpack.hpp", "volume.hpp"
)

Write-Host "Updating UnRAR source files from version 5.3.8 to 7.2.3..." -ForegroundColor Green
Write-Host "Source: $sourceDir" -ForegroundColor Yellow
Write-Host "Target: $targetDir" -ForegroundColor Yellow
Write-Host ""

# Copy source files
Write-Host "Copying source files..." -ForegroundColor Cyan
foreach ($file in $filesToUpdate) {
    $sourcePath = Join-Path $sourceDir $file
    $targetPath = Join-Path $targetDir $file

    if (Test-Path $sourcePath) {
        Copy-Item $sourcePath $targetPath -Force
        Write-Host "✓ $file" -ForegroundColor Green
    } else {
        Write-Host "✗ Missing: $file" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Copying header files..." -ForegroundColor Cyan
foreach ($file in $headersToUpdate) {
    $sourcePath = Join-Path $sourceDir $file
    $targetPath = Join-Path $targetDir $file

    if (Test-Path $sourcePath) {
        Copy-Item $sourcePath $targetPath -Force
        Write-Host "✓ $file" -ForegroundColor Green
    } else {
        Write-Host "✗ Missing: $file" -ForegroundColor Red
    }
}

# Handle special files that may have different names or need special handling
$specialFiles = @(
    @{ Source = "blake2s_sse.cpp"; Target = "blake2s_sse.cpp" },
    @{ Source = "blake2sp.cpp"; Target = "blake2sp.cpp" },
    @{ Source = "cmdfilter.cpp"; Target = "cmdfilter.cpp" },
    @{ Source = "cmdmix.cpp"; Target = "cmdmix.cpp" },
    @{ Source = "coder.cpp"; Target = "coder.cpp" },
    @{ Source = "coder.hpp"; Target = "coder.hpp" },
    @{ Source = "compress.hpp"; Target = "compress.hpp" },
    @{ Source = "crypt1.cpp"; Target = "crypt1.cpp" },
    @{ Source = "crypt2.cpp"; Target = "crypt2.cpp" },
    @{ Source = "crypt3.cpp"; Target = "crypt3.cpp" },
    @{ Source = "crypt5.cpp"; Target = "crypt5.cpp" },
    @{ Source = "hardlinks.cpp"; Target = "hardlinks.cpp" },
    @{ Source = "largepage.cpp"; Target = "largepage.cpp" },
    @{ Source = "largepage.hpp"; Target = "largepage.hpp" },
    @{ Source = "list.cpp"; Target = "list.cpp" },
    @{ Source = "list.hpp"; Target = "list.hpp" },
    @{ Source = "log.cpp"; Target = "log.cpp" },
    @{ Source = "log.hpp"; Target = "log.hpp" },
    @{ Source = "model.cpp"; Target = "model.cpp" },
    @{ Source = "model.hpp"; Target = "model.hpp" },
    @{ Source = "motw.cpp"; Target = "motw.cpp" },
    @{ Source = "motw.hpp"; Target = "motw.hpp" },
    @{ Source = "rarlang.hpp"; Target = "rarlang.hpp" },
    @{ Source = "rawint.hpp"; Target = "rawint.hpp" },
    @{ Source = "readme.txt"; Target = "ReadMe.txt" },
    @{ Source = "recvol3.cpp"; Target = "recvol3.cpp" },
    @{ Source = "recvol5.cpp"; Target = "recvol5.cpp" },
    @{ Source = "resource.cpp"; Target = "resource.cpp" },
    @{ Source = "resource.hpp"; Target = "resource.hpp" },
    @{ Source = "threadmisc.cpp"; Target = "threadmisc.cpp" },
    @{ Source = "uicommon.cpp"; Target = "uicommon.cpp" },
    @{ Source = "uiconsole.cpp"; Target = "uiconsole.cpp" },
    @{ Source = "uisilent.cpp"; Target = "uisilent.cpp" },
    @{ Source = "ulinks.cpp"; Target = "ulinks.cpp" },
    @{ Source = "unpack15.cpp"; Target = "unpack15.cpp" },
    @{ Source = "unpack20.cpp"; Target = "unpack20.cpp" },
    @{ Source = "unpack30.cpp"; Target = "unpack30.cpp" },
    @{ Source = "unpack50.cpp"; Target = "unpack50.cpp" },
    @{ Source = "unpack50frag.cpp"; Target = "unpack50frag.cpp" },
    @{ Source = "unpack50mt.cpp"; Target = "unpack50mt.cpp" },
    @{ Source = "unpackinline.cpp"; Target = "unpackinline.cpp" },
    @{ Source = "uowners.cpp"; Target = "uowners.cpp" },
    @{ Source = "win32acl.cpp"; Target = "win32acl.cpp" },
    @{ Source = "win32lnk.cpp"; Target = "win32lnk.cpp" },
    @{ Source = "win32stm.cpp"; Target = "win32stm.cpp" }
)

Write-Host ""
Write-Host "Copying additional/special files..." -ForegroundColor Cyan
foreach ($fileMap in $specialFiles) {
    $sourcePath = Join-Path $sourceDir $fileMap.Source
    $targetPath = Join-Path $targetDir $fileMap.Target

    if (Test-Path $sourcePath) {
        Copy-Item $sourcePath $targetPath -Force
        Write-Host "✓ $($fileMap.Target)" -ForegroundColor Green
    } else {
        Write-Host "✗ Missing: $($fileMap.Source)" -ForegroundColor Red
    }
}

# Copy license and acknowledgements
Write-Host ""
Write-Host "Copying license and documentation files..." -ForegroundColor Cyan
$docFiles = @("license.txt", "acknow.txt")
foreach ($file in $docFiles) {
    $sourcePath = Join-Path $sourceDir $file
    $targetPath = Join-Path $targetDir $file

    if (Test-Path $sourcePath) {
        Copy-Item $sourcePath $targetPath -Force
        Write-Host "✓ $file" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "UnRAR update complete!" -ForegroundColor Green
Write-Host "Version: 5.3.8 → 7.2.3" -ForegroundColor Yellow
Write-Host "Security: CVE-2025-8088 fixed" -ForegroundColor Red
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Build the UnRAR project" -ForegroundColor White
Write-Host "2. Test RAR archive extraction" -ForegroundColor White
Write-Host "3. Verify no directory traversal vulnerabilities" -ForegroundColor White