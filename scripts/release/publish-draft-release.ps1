#Requires -Version 7.0
<#
.SYNOPSIS
  Create or reuse a GitHub draft release and upload assets sequentially by release ID.

.DESCRIPTION
  Idempotent draft publisher:
  - Reuses an existing draft for the tag (or an explicit ReleaseId)
  - Creates a draft only when none exists
  - Uploads assets one-by-one with retry/backoff on transient failures
  - Skips assets that already match local size + SHA256
  - Replaces mismatched assets
  - Verifies the final remote asset set
  - Never publishes (draft always remains true)

  Avoids tag-based discovery right after create (drafts may appear as
  /releases/tag/untagged-... and softprops parallel upload races).
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$Tag,

	[Parameter(Mandatory = $true)]
	[string]$AssetDir,

	[Parameter(Mandatory = $false)]
	[string]$ReleaseId = '',

	[Parameter(Mandatory = $false)]
	[string]$Repository = $(if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { '' }),

	[Parameter(Mandatory = $false)]
	[string]$Name = '',

	[Parameter(Mandatory = $false)]
	[bool]$Prerelease = $true,

	[Parameter(Mandatory = $false)]
	[int]$MaxRetries = 4,

	[Parameter(Mandatory = $false)]
	[switch]$GenerateNotes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Fail([string]$Message)
{
	Write-Error $Message
	exit 1
}

function Assert-Gh
{
	if (-not (Get-Command gh -ErrorAction SilentlyContinue))
	{
		Write-Fail 'GitHub CLI (gh) is required.'
	}
	if (-not $env:GH_TOKEN -and -not $env:GITHUB_TOKEN)
	{
		Write-Fail 'GH_TOKEN or GITHUB_TOKEN must be set.'
	}
	if (-not $env:GH_TOKEN -and $env:GITHUB_TOKEN)
	{
		$env:GH_TOKEN = $env:GITHUB_TOKEN
	}
}

function Invoke-GhApiJson
{
	param(
		[Parameter(Mandatory = $true)][string[]]$GhArgs
	)
	# Do not merge stderr into stdout (2>&1) — that breaks JSON parsing.
	$stderrFile = [System.IO.Path]::GetTempFileName()
	try
	{
		$stdout = & gh @GhArgs 2>$stderrFile
		$code = $LASTEXITCODE
		$stderr = Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue
		if ($code -ne 0)
		{
			Write-Fail ("gh failed ({0}): {1}`n{2}" -f $code, (($stdout | Out-String)), $stderr)
		}
		$text = if ($null -eq $stdout) { '' } else { ($stdout | Out-String).Trim() }
		if (-not $text)
		{
			return $null
		}
		return ($text | ConvertFrom-Json)
	}
	finally
	{
		Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
	}
}

function Get-Sha256Hex([string]$Path)
{
	return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-TransientError([string]$Message)
{
	$m = $Message.ToLowerInvariant()
	return (
		$m -match 'timeout' -or
		$m -match 'temporar' -or
		$m -match 'rate limit' -or
		$m -match 'secondary rate' -or
		$m -match '502' -or
		$m -match '503' -or
		$m -match '504' -or
		$m -match 'error saving asset' -or
		$m -match 'server error' -or
		$m -match 'econnreset' -or
		$m -match 'unexpected eof'
	)
}

function Wait-Backoff([int]$Attempt)
{
	$seconds = [Math]::Min(60, [Math]::Pow(2, $Attempt))
	Write-Host "Retrying in ${seconds}s (attempt $Attempt)..."
	Start-Sleep -Seconds $seconds
}

Assert-Gh

if (-not $Repository)
{
	Write-Fail 'Repository is required (owner/name) or set GITHUB_REPOSITORY.'
}

$tagName = $Tag.Trim()
if ($tagName.StartsWith('refs/tags/'))
{
	$tagName = $tagName.Substring('refs/tags/'.Length)
}
if (-not $tagName.StartsWith('v'))
{
	Write-Fail "Tag must start with 'v' (got '$Tag')."
}

$version = $tagName.Substring(1)
$dir = (Resolve-Path -LiteralPath $AssetDir).Path
$releaseName = if ($Name) { $Name } else { "Envy $tagName" }

$expectedNames = @(
	"Envy-$version-x64.zip",
	"Envy-$version-x64-setup.exe",
	"Envy-$version-win32.zip",
	"Envy-$version-win32-setup.exe",
	'SHA256SUMS.txt'
)

foreach ($n in $expectedNames)
{
	$p = Join-Path $dir $n
	if (-not (Test-Path -LiteralPath $p))
	{
		Write-Fail "Local asset missing: $p"
	}
	if ((Get-Item -LiteralPath $p).Length -le 0)
	{
		Write-Fail "Local asset has zero size: $p"
	}
}

function Find-DraftByTag([string]$Repo, [string]$Tag)
{
	# List releases including drafts; do NOT use /releases/tags/{tag} (unreliable for drafts).
	$page = 1
	while ($true)
	{
		$batch = Invoke-GhApiJson -GhArgs @(
			'api',
			"repos/$Repo/releases?per_page=100&page=$page"
		)
		if (-not $batch -or @($batch).Count -eq 0)
		{
			return $null
		}
		foreach ($rel in @($batch))
		{
			if ($rel.tag_name -eq $Tag)
			{
				return $rel
			}
		}
		if (@($batch).Count -lt 100)
		{
			return $null
		}
		$page++
	}
}

function Get-ReleaseById([string]$Repo, [string]$Id)
{
	return Invoke-GhApiJson -GhArgs @('api', "repos/$Repo/releases/$Id")
}

function New-DraftRelease([string]$Repo, [string]$Tag, [string]$ReleaseName, [bool]$IsPrerelease, [bool]$WithNotes)
{
	$body = @{
		tag_name = $Tag
		name = $ReleaseName
		draft = $true
		prerelease = $IsPrerelease
		generate_release_notes = [bool]$WithNotes
	} | ConvertTo-Json -Compress

	$tmp = [System.IO.Path]::GetTempFileName()
	try
	{
		[System.IO.File]::WriteAllText($tmp, $body, [System.Text.UTF8Encoding]::new($false))
		$created = Invoke-GhApiJson -GhArgs @(
			'api',
			'--method', 'POST',
			"repos/$Repo/releases",
			'--input', $tmp
		)
	}
	finally
	{
		Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
	}

	if (-not $created -or -not $created.id)
	{
		Write-Fail 'Failed to create draft release (no id in response).'
	}
	return $created
}

$release = $null
if ($ReleaseId)
{
	Write-Host "Using explicit release_id=$ReleaseId"
	$release = Get-ReleaseById -Repo $Repository -Id $ReleaseId
}
else
{
	Write-Host "Looking up existing release for tag $tagName via releases list (not tag endpoint)..."
	$release = Find-DraftByTag -Repo $Repository -Tag $tagName
	if ($release)
	{
		Write-Host "Reusing existing release id=$($release.id) draft=$($release.draft) prerelease=$($release.prerelease)"
	}
	else
	{
		Write-Host "No existing release for $tagName; creating draft..."
		$release = New-DraftRelease -Repo $Repository -Tag $tagName -ReleaseName $releaseName -IsPrerelease $Prerelease -WithNotes:$GenerateNotes
		Write-Host "Created draft release id=$($release.id)"
	}
}

if (-not $release.draft)
{
	Write-Fail "Refusing to modify non-draft release id=$($release.id). Manual publish only."
}

# Keep prerelease flag aligned when reusing a draft.
$desiredPrerelease = [bool]$Prerelease
if ([bool]$release.prerelease -ne $desiredPrerelease -or $release.name -ne $releaseName)
{
	Write-Host "Updating release metadata (name/prerelease); draft stays true."
	$patch = @{
		name = $releaseName
		draft = $true
		prerelease = $desiredPrerelease
	} | ConvertTo-Json -Compress
	$tmp = [System.IO.Path]::GetTempFileName()
	try
	{
		[System.IO.File]::WriteAllText($tmp, $patch, [System.Text.UTF8Encoding]::new($false))
		$release = Invoke-GhApiJson -GhArgs @(
			'api',
			'--method', 'PATCH',
			"repos/$Repository/releases/$($release.id)",
			'--input', $tmp
		)
	}
	finally
	{
		Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
	}
}

if (-not $release.draft)
{
	Write-Fail 'Release left draft=false unexpectedly; aborting.'
}

$releaseIdValue = [string]$release.id
Write-Host "Working release_id=$releaseIdValue html_url=$($release.html_url)"

function Get-RemoteAssets([string]$Repo, [string]$Id)
{
	$rel = Get-ReleaseById -Repo $Repo -Id $Id
	return @($rel.assets)
}

function Remove-RemoteAsset([string]$Repo, $Asset)
{
	Write-Host "Deleting remote asset $($Asset.name) (id=$($Asset.id), size=$($Asset.size))"
	& gh api --method DELETE "repos/$Repo/releases/assets/$($Asset.id)" | Out-Null
	if ($LASTEXITCODE -ne 0)
	{
		Write-Fail "Failed to delete asset id=$($Asset.id)"
	}
}

function Get-RemoteAssetBytes([string]$Repo, [string]$AssetId, [string]$OutFile)
{
	$token = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }
	$uri = "https://api.github.com/repos/$Repo/releases/assets/$AssetId"
	$headers = @{
		Authorization = "Bearer $token"
		Accept = 'application/octet-stream'
		'User-Agent' = 'Envy-release-pipeline'
	}
	try
	{
		Invoke-WebRequest -Uri $uri -Headers $headers -OutFile $OutFile -UseBasicParsing | Out-Null
	}
	catch
	{
		Write-Fail "Failed to download remote asset id=$AssetId for comparison: $_"
	}
}

function Send-Asset([string]$Repo, [string]$Id, [string]$FilePath, [string]$AssetName, [int]$Retries)
{
	# Asset uploads must hit uploads.github.com (api.github.com returns 404).
	$uploadPath = "https://uploads.github.com/repos/$Repo/releases/$Id/assets?name=$([uri]::EscapeDataString($AssetName))"
	$attempt = 0
	while ($true)
	{
		$attempt++
		Write-Host "Uploading $AssetName (attempt $attempt)..."
		$errFile = [System.IO.Path]::GetTempFileName()
		try
		{
			& gh api --method POST `
				-H 'Content-Type: application/octet-stream' `
				--input $FilePath `
				$uploadPath 1>$null 2>$errFile
			$code = $LASTEXITCODE
			$errText = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue
			if ($code -eq 0)
			{
				Write-Host "Uploaded $AssetName"
				return
			}
			if ($attempt -lt $Retries -and (Test-TransientError $errText))
			{
				Write-Host "Transient upload error for ${AssetName}: $errText"
				Wait-Backoff -Attempt $attempt
				continue
			}
			Write-Fail "Failed uploading ${AssetName} after $attempt attempt(s): $errText"
		}
		finally
		{
			Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
		}
	}
}

# Sequential deterministic upload order.
foreach ($assetName in $expectedNames)
{
	$localPath = Join-Path $dir $assetName
	$localSize = (Get-Item -LiteralPath $localPath).Length
	$localHash = Get-Sha256Hex $localPath

	$remoteAssets = Get-RemoteAssets -Repo $Repository -Id $releaseIdValue
	$existing = @($remoteAssets | Where-Object { $_.name -eq $assetName })

	if ($existing.Count -gt 1)
	{
		Write-Host "Found $($existing.Count) duplicates named $assetName; deleting all before re-upload."
		foreach ($dup in $existing)
		{
			Remove-RemoteAsset -Repo $Repository -Asset $dup
		}
		$existing = @()
	}

	if ($existing.Count -eq 1)
	{
		$remote = $existing[0]
		if ($remote.state -ne 'uploaded')
		{
			Write-Host "Remote asset $assetName state=$($remote.state); replacing."
			Remove-RemoteAsset -Repo $Repository -Asset $remote
		}
		elseif ([int64]$remote.size -eq [int64]$localSize)
		{
			$tmpDownload = Join-Path ([System.IO.Path]::GetTempPath()) ("envy-asset-" + [guid]::NewGuid().ToString('N'))
			try
			{
				Get-RemoteAssetBytes -Repo $Repository -AssetId ([string]$remote.id) -OutFile $tmpDownload
				$remoteHash = Get-Sha256Hex $tmpDownload
				if ($remoteHash -eq $localHash)
				{
					Write-Host "Keeping existing asset $assetName (size+sha256 match)."
					continue
				}
				Write-Host "Remote $assetName sha mismatch; replacing."
			}
			finally
			{
				Remove-Item -LiteralPath $tmpDownload -Force -ErrorAction SilentlyContinue
			}
			Remove-RemoteAsset -Repo $Repository -Asset $remote
		}
		else
		{
			Write-Host "Remote $assetName size mismatch (remote=$($remote.size) local=$localSize); replacing."
			Remove-RemoteAsset -Repo $Repository -Asset $remote
		}
	}

	Send-Asset -Repo $Repository -Id $releaseIdValue -FilePath $localPath -AssetName $assetName -Retries $MaxRetries
}

# Final verification against GitHub API.
$final = Get-ReleaseById -Repo $Repository -Id $releaseIdValue
if (-not $final.draft)
{
	Write-Fail 'Final check: release is not draft=true.'
}
if ([bool]$final.prerelease -ne $desiredPrerelease)
{
	Write-Fail "Final check: prerelease=$($final.prerelease) expected $desiredPrerelease"
}

$finalAssets = @($final.assets)
$byName = @{}
foreach ($a in $finalAssets)
{
	if ($byName.ContainsKey($a.name))
	{
		Write-Fail "Final check: duplicate asset name $($a.name)"
	}
	$byName[$a.name] = $a
}

foreach ($assetName in $expectedNames)
{
	if (-not $byName.ContainsKey($assetName))
	{
		Write-Fail "Final check: missing asset $assetName"
	}
	$a = $byName[$assetName]
	if ($a.state -ne 'uploaded')
	{
		Write-Fail "Final check: asset $assetName state=$($a.state)"
	}
	if ([int64]$a.size -le 0)
	{
		Write-Fail "Final check: asset $assetName has size $($a.size)"
	}
	$localSize = (Get-Item -LiteralPath (Join-Path $dir $assetName)).Length
	if ([int64]$a.size -ne [int64]$localSize)
	{
		Write-Fail "Final check: size mismatch for $assetName remote=$($a.size) local=$localSize"
	}
	Write-Host "Final OK: $assetName size=$($a.size) state=$($a.state)"
}

Write-Host "publish-draft-release: PASS (release_id=$releaseIdValue, draft=true, assets=$($expectedNames.Count))"
Write-Host "RELEASE_ID=$releaseIdValue"
if ($env:GITHUB_OUTPUT)
{
	Add-Content -Path $env:GITHUB_OUTPUT -Value "release_id=$releaseIdValue"
	Add-Content -Path $env:GITHUB_OUTPUT -Value "html_url=$($final.html_url)"
}
exit 0
