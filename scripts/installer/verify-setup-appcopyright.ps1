#Requires -Version 7.0
<#
.SYNOPSIS
  Verify an Envy setup executable exposes the expected AppCopyright / LegalCopyright text.
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory)]
	[string]$SetupExePath,
	[string]$ExpectedSubstring = '© 2016-2020 Envy Development Team'
)

$ErrorActionPreference = 'Stop'

function Find-Bytes {
	param([byte[]]$Buffer, [byte[]]$Needle)
	for ($i = 0; $i -le $Buffer.Length - $Needle.Length; $i++) {
		$ok = $true
		for ($j = 0; $j -lt $Needle.Length; $j++) {
			if ($Buffer[$i + $j] -ne $Needle[$j]) { $ok = $false; break }
		}
		if ($ok) { return $i }
	}
	return $null
}

if (-not (Test-Path -LiteralPath $SetupExePath)) {
	throw "Setup executable not found: $SetupExePath"
}

$vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($SetupExePath)
$haystack = ($vi.LegalCopyright, $vi.Comments, $vi.ProductName | Where-Object { $_ }) -join ' '

$foundInVersionInfo = $haystack.Contains($ExpectedSubstring)
$bytes = [System.IO.File]::ReadAllBytes($SetupExePath)
$utf8 = [System.Text.Encoding]::UTF8.GetBytes($ExpectedSubstring)
$utf16 = [System.Text.Encoding]::Unicode.GetBytes($ExpectedSubstring)
$foundInImage = ($null -ne (Find-Bytes $bytes $utf8)) -or ($null -ne (Find-Bytes $bytes $utf16))

if (-not $foundInVersionInfo -and -not $foundInImage) {
	throw "Expected copyright metadata not found in $SetupExePath. LegalCopyright='$($vi.LegalCopyright)'"
}

$corruptAscii = [System.Text.Encoding]::UTF8.GetBytes("? 2016-2020 Envy Development Team")
if ($haystack -match '\? 2016-2020' -or ($null -ne (Find-Bytes $bytes $corruptAscii))) {
	throw "Corrupted question-mark copyright detected in $SetupExePath"
}

Write-Host "OK: setup metadata contains expected copyright for $SetupExePath"
