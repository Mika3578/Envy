<#
.SYNOPSIS
  Writes an anonymised copy of an Envy.log (IPs, paths, hashes and e-mails replaced).
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$LogFile)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $LogFile)) { throw "File not found: $LogFile" }
$ipMap = @{}
function Mask-Ip([string]$ip) {
    if (-not $ipMap.ContainsKey($ip)) { $ipMap[$ip] = '<ip{0}>' -f ($ipMap.Count + 1) }
    return $ipMap[$ip]
}
$out = [System.IO.Path]::ChangeExtension($LogFile, '.anonymised.txt')
Get-Content -LiteralPath $LogFile -Encoding UTF8 | Where-Object { $_ -match 'Kad2|Kad nodes\.dat|Kademlia' } | ForEach-Object {
    $l = $_
    $l = [regex]::Replace($l, '\b(\d{1,3}\.){3}\d{1,3}\b', { param($m) Mask-Ip $m.Value })
    $l = [regex]::Replace($l, '[A-Za-z]:\\[^\s"'']+', '<path>')
    $l = [regex]::Replace($l, '\b[0-9A-Fa-f]{32,64}\b', '<hex>')
    $l = [regex]::Replace($l, 'urn:[A-Za-z0-9:]+', 'urn:<hash>')
    $l = [regex]::Replace($l, '[\w.+-]+@[\w-]+\.[\w.-]+', '<email>')
    $l
} | Set-Content -LiteralPath $out -Encoding UTF8
Write-Host "Written: $out"
