#Requires -Version 5.1
<#
.SYNOPSIS
  Clone or update local P2P reference checkouts for Envy developers/agents.

.DESCRIPTION
  Reads tools/references/catalog.json and clones repositories into
  Examples/References/<id>/ (gitignored). Never modifies Envy git state,
  never builds references, never adds submodules.

.EXAMPLE
  ./tools/references/sync-references.ps1 -Group ed2k-immediate
.EXAMPLE
  ./tools/references/sync-references.ps1 -Project emule-community
.EXAMPLE
  ./tools/references/sync-references.ps1 -List
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
	[string]$Group,
	[string]$Project,
	[string]$Root,
	[string]$CatalogPath,
	[switch]$List,
	[switch]$Status
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RepoRoot {
	$here = $PSScriptRoot
	# tools/references -> repo root
	return (Resolve-Path (Join-Path $here '..\..')).Path
}

function Read-Catalog {
	param([string]$Path)
	if (-not (Test-Path -LiteralPath $Path)) {
		throw "Catalog not found: $Path"
	}
	$raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
	return ($raw | ConvertFrom-Json)
}

function Write-ProjectRow {
	param($Item)
	$groups = @($Item.groups) -join ','
	'{0,-22} {1,-6} {2,-16} {3}' -f $Item.id, $Item.priority, $Item.authority, $groups
}

function Select-Projects {
	param($Catalog, [string]$GroupName, [string]$ProjectId)

	$all = @($Catalog.projects)
	if ($ProjectId) {
		$match = @($all | Where-Object { $_.id -eq $ProjectId })
		if ($match.Count -eq 0) {
			$known = ($all | ForEach-Object { $_.id }) -join ', '
			throw "Unknown project '$ProjectId'. Known: $known"
		}
		return $match
	}
	if ($GroupName) {
		$groupKeys = @($Catalog.groups.PSObject.Properties.Name)
		if ($groupKeys -notcontains $GroupName) {
			$known = ($groupKeys | Sort-Object) -join ', '
			throw "Unknown group '$GroupName'. Known: $known"
		}
		$match = @($all | Where-Object { @($_.groups) -contains $GroupName })
		if ($match.Count -eq 0) {
			throw "Group '$GroupName' has no projects in the catalog."
		}
		return $match
	}
	# Default: syncDefault projects only
	return @($all | Where-Object { $_.syncDefault -eq $true })
}

function Invoke-Git {
	param(
		[Parameter(Mandatory = $true)]
		[string[]]$GitArgs,
		[switch]$PassThru
	)
	# Keep native git stdout/stderr out of the PowerShell success stream so
	# functions do not accidentally return String[] + object mixtures.
	$prevNative = $null
	if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
		$prevNative = $PSNativeCommandUseErrorActionPreference
		$PSNativeCommandUseErrorActionPreference = $false
	}
	try {
		$out = & git @GitArgs 2>&1
		$code = $LASTEXITCODE
		if ($PassThru) {
			return [pscustomobject]@{
				ExitCode = $code
				Output   = @($out | ForEach-Object { "$_" })
			}
		}
		return $code
	}
	finally {
		if ($null -ne $prevNative) {
			$PSNativeCommandUseErrorActionPreference = $prevNative
		}
	}
}

function Get-GitHeadInfo {
	param([string]$Path)
	$branch = (Invoke-Git -GitArgs @('-C', $Path, 'rev-parse', '--abbrev-ref', 'HEAD') -PassThru).Output | Select-Object -First 1
	$sha = (Invoke-Git -GitArgs @('-C', $Path, 'rev-parse', '--short', 'HEAD') -PassThru).Output | Select-Object -First 1
	$date = (Invoke-Git -GitArgs @('-C', $Path, 'show', '-s', '--format=%ci', 'HEAD') -PassThru).Output | Select-Object -First 1
	$tagInfo = Invoke-Git -GitArgs @('-C', $Path, 'describe', '--tags', '--exact-match', 'HEAD') -PassThru
	$tag = if ($tagInfo.ExitCode -eq 0) { $tagInfo.Output | Select-Object -First 1 } else { '' }
	[pscustomobject]@{
		Branch = if ($branch) { "$branch".Trim() } else { '?' }
		Sha    = if ($sha) { "$sha".Trim() } else { '?' }
		Date   = if ($date) { "$date".Trim() } else { '?' }
		Tag    = if ($tag) { "$tag".Trim() } else { '' }
	}
}

function Sync-OneProject {
	param(
		$Item,
		[string]$LocalRoot,
		[switch]$StatusOnly
	)

	$dir = Join-Path $LocalRoot $Item.id
	$result = [pscustomobject]@{
		Id      = $Item.id
		Ok      = $false
		Action  = ''
		Path    = $dir
		Message = ''
		Head    = $null
	}

	if ($StatusOnly) {
		if (-not (Test-Path -LiteralPath (Join-Path $dir '.git'))) {
			# Status mode reports absence without treating it as a hard failure.
			$result.Ok = $true
			$result.Action = 'missing'
			$result.Message = 'not cloned'
			return $result
		}
		$result.Ok = $true
		$result.Action = 'present'
		$result.Head = Get-GitHeadInfo -Path $dir
		$tagPart = if ($result.Head.Tag) { " tag=$($result.Head.Tag)" } else { '' }
		$result.Message = "branch=$($result.Head.Branch) sha=$($result.Head.Sha)$tagPart date=$($result.Head.Date)"
		return $result
	}

	if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
		$result.Message = 'git is not available on PATH'
		return $result
	}

	try {
		if (Test-Path -LiteralPath (Join-Path $dir '.git')) {
			$result.Action = 'update'
			if ($PSCmdlet.ShouldProcess($dir, "git fetch/pull $($Item.id)")) {
				if ((Invoke-Git -GitArgs @('-C', $dir, 'remote', 'set-url', 'origin', $Item.url)) -ne 0) {
					throw "git remote set-url failed for $($Item.id)"
				}
				if ((Invoke-Git -GitArgs @('-C', $dir, 'fetch', '--tags', '--prune', 'origin')) -ne 0) {
					throw "git fetch failed for $($Item.id) ($($Item.url))"
				}
				$ref = $Item.defaultRef
				if ((Invoke-Git -GitArgs @('-C', $dir, 'checkout', $ref, '--')) -ne 0) {
					throw "git checkout '$ref' failed for $($Item.id)"
				}
				$branch = ((Invoke-Git -GitArgs @('-C', $dir, 'rev-parse', '--abbrev-ref', 'HEAD') -PassThru).Output | Select-Object -First 1)
				$branch = if ($branch) { "$branch".Trim() } else { 'HEAD' }
				if ($branch -ne 'HEAD') {
					if ((Invoke-Git -GitArgs @('-C', $dir, 'pull', '--ff-only', 'origin', $branch)) -ne 0) {
						throw "git pull --ff-only failed for $($Item.id) (local dirty or diverged?)"
					}
				}
			}
		}
		else {
			$result.Action = 'clone'
			$parent = Split-Path -Parent $dir
			if (-not (Test-Path -LiteralPath $parent)) {
				if ($PSCmdlet.ShouldProcess($parent, 'create references directory')) {
					New-Item -ItemType Directory -Path $parent -Force | Out-Null
				}
			}
			if (Test-Path -LiteralPath $dir) {
				throw "Path exists but is not a git clone: $dir"
			}
			if ($PSCmdlet.ShouldProcess($dir, "git clone $($Item.url)")) {
				$code = Invoke-Git -GitArgs @('clone', '--branch', $Item.defaultRef, '--single-branch', $Item.url, $dir)
				if ($code -ne 0) {
					$code = Invoke-Git -GitArgs @('clone', $Item.url, $dir)
					if ($code -ne 0) {
						throw "git clone failed for $($Item.id) ($($Item.url))"
					}
					if ((Invoke-Git -GitArgs @('-C', $dir, 'checkout', $Item.defaultRef, '--')) -ne 0) {
						throw "clone succeeded but checkout '$($Item.defaultRef)' failed for $($Item.id)"
					}
				}
			}
		}

		$result.Ok = $true
		if (Test-Path -LiteralPath (Join-Path $dir '.git')) {
			$result.Head = Get-GitHeadInfo -Path $dir
			$tagPart = if ($result.Head.Tag) { " tag=$($result.Head.Tag)" } else { '' }
			$result.Message = "branch=$($result.Head.Branch) sha=$($result.Head.Sha)$tagPart date=$($result.Head.Date)"
		}
		else {
			$result.Message = 'skipped (WhatIf) or incomplete'
		}
	}
	catch {
		$result.Ok = $false
		$result.Message = $_.Exception.Message
	}

	# Ensure a single object is returned (no accidental pipeline concatenation).
	Write-Output -NoEnumerate $result
}

# --- main ---
$repoRoot = Get-RepoRoot
if (-not $CatalogPath) {
	$CatalogPath = Join-Path $PSScriptRoot 'catalog.json'
}
$catalog = Read-Catalog -Path $CatalogPath

if (-not $Root) {
	$Root = Join-Path $repoRoot $catalog.localRoot
}
else {
	if (-not [System.IO.Path]::IsPathRooted($Root)) {
		$Root = Join-Path $repoRoot $Root
	}
}

Write-Host "Envy root : $repoRoot"
Write-Host "Local root: $Root"
Write-Host "Catalog   : $CatalogPath"
Write-Host ''

if ($List) {
	Write-Host 'Groups:'
	foreach ($g in ($catalog.groups.PSObject.Properties | Sort-Object Name)) {
		Write-Host ("  {0,-16} {1}" -f $g.Name, $g.Value)
	}
	Write-Host ''
	Write-Host ('{0,-22} {1,-6} {2,-16} {3}' -f 'Id', 'Prio', 'Authority', 'Groups')
	Write-Host ('-' * 72)
	foreach ($p in ($catalog.projects | Sort-Object id)) {
		Write-Host (Write-ProjectRow -Item $p)
	}
	exit 0
}

if ($Group -and $Project) {
	throw 'Specify either -Group or -Project, not both.'
}

$selected = Select-Projects -Catalog $catalog -GroupName $Group -ProjectId $Project
Write-Host ("Selected {0} project(s)." -f $selected.Count)
Write-Host ''

$failures = New-Object System.Collections.Generic.List[string]
foreach ($item in $selected) {
	Write-Host ("==> {0} ({1})" -f $item.id, $item.url)
	$r = Sync-OneProject -Item $item -LocalRoot $Root -StatusOnly:$Status
	if ($r.Ok) {
		Write-Host ("    OK [{0}] {1}" -f $r.Action, $r.Message)
	}
	else {
		Write-Host ("    FAIL [{0}] {1}" -f $r.Action, $r.Message) -ForegroundColor Red
		$failures.Add($item.id) | Out-Null
	}
}

Write-Host ''
# Safety: never stage Examples into Envy
$envyStatus = & git -C $repoRoot status --porcelain -- Examples 2>$null
if ($envyStatus) {
	Write-Host 'Note: git status shows changes under Examples/ (should remain untracked/ignored).' -ForegroundColor Yellow
}

if ($failures.Count -gt 0) {
	Write-Error ("Failed: {0}" -f ($failures -join ', '))
	exit 1
}

Write-Host 'Done. Reference trees stay outside Envy git history (Examples/ is gitignored).'
exit 0
