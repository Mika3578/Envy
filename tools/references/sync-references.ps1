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
	# Default: syncDefault projects only.
	# StrictMode-safe: omit/null syncDefault must not terminate selection.
	return @(
		$all | Where-Object {
			$prop = $_.PSObject.Properties['syncDefault']
			($null -ne $prop) -and ($prop.Value -eq $true)
		}
	)
}

function Assert-SafeProjectId {
	param([string]$Id)
	if ($Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
		throw "Invalid project id '$Id' (allowed: letters, digits, '.', '_', '-')."
	}
}

function Resolve-ProjectDir {
	param(
		[string]$LocalRoot,
		[string]$ProjectId
	)
	Assert-SafeProjectId -Id $ProjectId
	$rootFull = [System.IO.Path]::GetFullPath($LocalRoot)
	$dirFull = [System.IO.Path]::GetFullPath((Join-Path $rootFull $ProjectId))
	$prefix = if ($rootFull.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
		$rootFull
	}
	else {
		$rootFull + [System.IO.Path]::DirectorySeparatorChar
	}
	if (-not ($dirFull.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
			$dirFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase))) {
		throw "Project path escapes local root: $ProjectId"
	}
	return $dirFull
}

function Invoke-Git {
	param(
		[Parameter(Mandatory = $true)]
		[string[]]$GitArgs,
		[switch]$PassThru
	)
	# Keep native git stdout/stderr out of the PowerShell success stream so
	# functions do not accidentally return String[] + object mixtures.
	# Under $ErrorActionPreference=Stop, stderr-as-ErrorRecord from `2>&1`
	# must not terminate (e.g. git describe with no exact tag).
	$prevNative = $null
	if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
		$prevNative = $PSNativeCommandUseErrorActionPreference
		$PSNativeCommandUseErrorActionPreference = $false
	}
	$prevEap = $ErrorActionPreference
	$ErrorActionPreference = 'Continue'
	try {
		$out = & git @GitArgs 2>&1
		$code = $LASTEXITCODE
		$lines = @($out | ForEach-Object { "$_" })
		# -PassThru kept for call-site clarity; both paths return the same shape.
		return [pscustomobject]@{
			ExitCode = $code
			Output   = $lines
		}
	}
	finally {
		$ErrorActionPreference = $prevEap
		if ($null -ne $prevNative) {
			$PSNativeCommandUseErrorActionPreference = $prevNative
		}
	}
}

function Assert-GitOk {
	param(
		$GitResult,
		[string]$Context
	)
	if ($GitResult.ExitCode -ne 0) {
		$detail = ($GitResult.Output | Where-Object { $_ -and $_.Trim() }) -join ' | '
		if (-not $detail) { $detail = "exit $($GitResult.ExitCode)" }
		throw "$Context : $detail"
	}
}

function Get-GitHeadInfo {
	param([string]$Path)
	$branchInfo = Invoke-Git -GitArgs @('-C', $Path, 'rev-parse', '--abbrev-ref', 'HEAD') -PassThru
	Assert-GitOk -GitResult $branchInfo -Context "git rev-parse --abbrev-ref in $Path"
	$shaInfo = Invoke-Git -GitArgs @('-C', $Path, 'rev-parse', '--short', 'HEAD') -PassThru
	Assert-GitOk -GitResult $shaInfo -Context "git rev-parse --short in $Path"
	$dateInfo = Invoke-Git -GitArgs @('-C', $Path, 'show', '-s', '--format=%ci', 'HEAD') -PassThru
	Assert-GitOk -GitResult $dateInfo -Context "git show HEAD date in $Path"
	$tagInfo = Invoke-Git -GitArgs @('-C', $Path, 'describe', '--tags', '--exact-match', 'HEAD') -PassThru
	$tag = if ($tagInfo.ExitCode -eq 0) { $tagInfo.Output | Select-Object -First 1 } else { '' }
	[pscustomobject]@{
		Branch = ("$($branchInfo.Output | Select-Object -First 1)").Trim()
		Sha    = ("$($shaInfo.Output | Select-Object -First 1)").Trim()
		Date   = ("$($dateInfo.Output | Select-Object -First 1)").Trim()
		Tag    = if ($tag) { "$tag".Trim() } else { '' }
	}
}

function Sync-OneProject {
	param(
		$Item,
		[string]$LocalRoot,
		[switch]$StatusOnly
	)

	$result = [pscustomobject]@{
		Id      = $Item.id
		Ok      = $false
		Action  = ''
		Path    = ''
		Message = ''
		Head    = $null
	}

	try {
		$dir = Resolve-ProjectDir -LocalRoot $LocalRoot -ProjectId $Item.id
		$result.Path = $dir
	}
	catch {
		$result.Message = $_.Exception.Message
		Write-Output -NoEnumerate $result
		return
	}

	if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
		$result.Message = 'git is not available on PATH'
		Write-Output -NoEnumerate $result
		return
	}

	if ($StatusOnly) {
		try {
			if (-not (Test-Path -LiteralPath (Join-Path $dir '.git'))) {
				$result.Ok = $true
				$result.Action = 'missing'
				$result.Message = 'not cloned'
				Write-Output -NoEnumerate $result
				return
			}
			$result.Action = 'present'
			$result.Head = Get-GitHeadInfo -Path $dir
			$tagPart = if ($result.Head.Tag) { " tag=$($result.Head.Tag)" } else { '' }
			$result.Message = "branch=$($result.Head.Branch) sha=$($result.Head.Sha)$tagPart date=$($result.Head.Date)"
			$result.Ok = $true
		}
		catch {
			$result.Ok = $false
			$result.Action = 'broken'
			$result.Message = $_.Exception.Message
		}
		Write-Output -NoEnumerate $result
		return
	}

	try {
		if (Test-Path -LiteralPath (Join-Path $dir '.git')) {
			$result.Action = 'update'
			if ($PSCmdlet.ShouldProcess($dir, "git fetch/pull $($Item.id)")) {
				Assert-GitOk -GitResult (Invoke-Git -GitArgs @('-C', $dir, 'remote', 'set-url', 'origin', $Item.url)) -Context "git remote set-url $($Item.id)"
				Assert-GitOk -GitResult (Invoke-Git -GitArgs @('-C', $dir, 'fetch', '--tags', '--prune', 'origin')) -Context "git fetch $($Item.id) ($($Item.url))"
				$ref = $Item.defaultRef
				Assert-GitOk -GitResult (Invoke-Git -GitArgs @('-C', $dir, 'checkout', $ref)) -Context "git checkout '$ref' $($Item.id)"
				$branchInfo = Invoke-Git -GitArgs @('-C', $dir, 'rev-parse', '--abbrev-ref', 'HEAD') -PassThru
				Assert-GitOk -GitResult $branchInfo -Context "git rev-parse after checkout $($Item.id)"
				$branch = ("$($branchInfo.Output | Select-Object -First 1)").Trim()
				if ($branch -ne 'HEAD') {
					Assert-GitOk -GitResult (Invoke-Git -GitArgs @('-C', $dir, 'pull', '--ff-only', 'origin', $branch)) -Context "git pull --ff-only $($Item.id)"
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
				$clone = Invoke-Git -GitArgs @('clone', '--branch', $Item.defaultRef, '--single-branch', $Item.url, $dir)
				if ($clone.ExitCode -ne 0) {
					$clone = Invoke-Git -GitArgs @('clone', $Item.url, $dir)
					Assert-GitOk -GitResult $clone -Context "git clone $($Item.id) ($($Item.url))"
					Assert-GitOk -GitResult (Invoke-Git -GitArgs @('-C', $dir, 'checkout', $Item.defaultRef)) -Context "checkout '$($Item.defaultRef)' after clone $($Item.id)"
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

# @() re-wraps PowerShell's single-element / empty return unwrap so .Count is safe under StrictMode.
$selected = @(Select-Projects -Catalog $catalog -GroupName $Group -ProjectId $Project)
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
