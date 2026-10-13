param
(
	[Parameter(Mandatory = $true)]
	[string]$InputFile,
	[Parameter(Mandatory = $true)]
	[string]$OutputFile
)

$ErrorActionPreference = 'Stop'

$inputPath = [System.IO.Path]::GetFullPath($InputFile)
$outputPath = [System.IO.Path]::GetFullPath($OutputFile)
$temporaryPath = $outputPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
$backupPath = $outputPath + '.' + [Guid]::NewGuid().ToString('N') + '.bak'
$inputStream = $null
$outputStream = $null
$gzipStream = $null

try
{
	$inputStream = [System.IO.File]::Open($inputPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
	$outputStream = [System.IO.File]::Open($temporaryPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
	$gzipStream = New-Object System.IO.Compression.GZipStream($outputStream, [System.IO.Compression.CompressionMode]::Compress, $true)
	$inputStream.CopyTo($gzipStream)
	$gzipStream.Dispose()
	$gzipStream = $null
	$outputStream.Flush($true)
	$outputStream.Dispose()
	$outputStream = $null
	$inputStream.Dispose()
	$inputStream = $null

	if ([System.IO.File]::Exists($outputPath))
	{
		[System.IO.File]::Replace($temporaryPath, $outputPath, $backupPath)
		[System.IO.File]::Delete($backupPath)
	}
	else
	{
		[System.IO.File]::Move($temporaryPath, $outputPath)
	}
}
catch
{
	if ($null -ne $gzipStream) { $gzipStream.Dispose() }
	if ($null -ne $outputStream) { $outputStream.Dispose() }
	if ($null -ne $inputStream) { $inputStream.Dispose() }
	if ([System.IO.File]::Exists($temporaryPath)) { [System.IO.File]::Delete($temporaryPath) }
	throw
}
