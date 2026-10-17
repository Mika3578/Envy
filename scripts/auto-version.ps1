#Requires -Version 7.0
<#
.SYNOPSIS
  Bump the Envy product version in version.json (and optionally Envy.rc / CHANGELOG.md).

.DESCRIPTION
  Version convention (checked by scripts/release/verify-version.ps1):
    - fullVersion     = M.m.p[-<label>.N]          e.g. 4.2.0-preview.3
    - displayVersion  = M.m.p[ <Label> N]          e.g. 4.2.0 Preview 3
    - build           = release counter within M.m.p (1 for the first release of
                        a new M.m.p, +1 for every following prerelease/final)
    - git.intendedTag = v<fullVersion>
    - Envy.rc FILEVERSION/PRODUCTVERSION = M,m,p,build; FileVersion = M.m.p.build;
      ProductVersion = displayVersion

  Actions (exactly one):
    -PreRelease                  next prerelease of the current M.m.p
                                 (preview.2 -> preview.3; a different label restarts at .1)
    -IncrementPatch/Minor/Major  next M.m.p, build reset to 1; add -PreRelease to start
                                 at <label>.1 instead of a final version
    -Final                       promote the current prerelease to the final M.m.p

  The script never commits, pushes or tags.
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$VersionFile = "version.json",
    [Parameter(Mandatory=$false)]
    [switch]$IncrementPatch,
    [Parameter(Mandatory=$false)]
    [switch]$IncrementMinor,
    [Parameter(Mandatory=$false)]
    [switch]$IncrementMajor,
    [Parameter(Mandatory=$false)]
    [switch]$PreRelease,
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[a-z]+$')]
    [string]$PreReleaseLabel = "preview",
    [Parameter(Mandatory=$false)]
    [switch]$Final,
    [Parameter(Mandatory=$false)]
    [switch]$UpdateFiles,
    [Parameter(Mandatory=$false)]
    [string]$Branch = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$VersionFilePath = [System.IO.Path]::IsPathRooted($VersionFile) ? $VersionFile : (Join-Path $ProjectRoot $VersionFile)

function Read-TextFile {
    param([string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $offset = $hasBom ? 3 : 0
    $text = [System.Text.UTF8Encoding]::new($false).GetString($bytes, $offset, $bytes.Length - $offset)
    $newline = $text.Contains("`r`n") ? "`r`n" : "`n"
    return [pscustomobject]@{ Text = $text; HasBom = $hasBom; Newline = $newline }
}

function Write-TextFile {
    param([string]$Path, [string]$Text, [bool]$HasBom)

    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($HasBom))
}

function Get-PreReleaseDisplayName {
    param([string]$Label)

    if ($Label -eq "rc") {
        return "RC"
    }
    return $Label.Substring(0, 1).ToUpperInvariant() + $Label.Substring(1)
}

function Set-JsonProperty {
    param($Object, [string]$Name, $Value)

    if ($Object.PSObject.Properties[$Name]) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Update-EnvyRc {
    param($VersionData)

    $rcPath = Join-Path $ProjectRoot "Envy" "Envy.rc"
    $file = Read-TextFile $rcPath
    $text = $file.Text

    $csv = '{0},{1},{2},{3}' -f $VersionData.major, $VersionData.minor, $VersionData.patch, $VersionData.build
    $dotted = '{0}.{1}.{2}.{3}' -f $VersionData.major, $VersionData.minor, $VersionData.patch, $VersionData.build

    # .NET regex is case-sensitive: FILEVERSION (fixed block) never matches "FileVersion" (string table).
    $replacements = @(
        @{ Pattern = '(?m)^(\s*PRODUCTVERSION\s+)\d+,\d+,\d+,\d+'; Value = "`${1}$csv" },
        @{ Pattern = '(?m)^(\s*FILEVERSION\s+)\d+,\d+,\d+,\d+'; Value = "`${1}$csv" },
        @{ Pattern = '(VALUE\s+"ProductVersion",\s+")[^"]*(")'; Value = "`${1}$($VersionData.displayVersion)`${2}" },
        @{ Pattern = '(VALUE\s+"FileVersion",\s+")[^"]*(")'; Value = "`${1}$dotted`${2}" }
    )

    foreach ($r in $replacements) {
        $count = [regex]::Matches($text, $r.Pattern).Count
        if ($count -ne 1) {
            throw "Envy.rc: expected exactly one match for '$($r.Pattern)', found $count."
        }
        $text = [regex]::Replace($text, $r.Pattern, $r.Value)
    }

    Write-TextFile $rcPath $text $file.HasBom
    Write-Host "  Updated Envy/Envy.rc ($csv, '$($VersionData.displayVersion)')" -ForegroundColor Gray
}

function Update-Changelog {
    param($VersionData)

    $changelogPath = Join-Path $ProjectRoot "CHANGELOG.md"
    if (-not (Test-Path $changelogPath)) {
        return
    }

    $file = Read-TextFile $changelogPath
    $heading = "## [$($VersionData.fullVersion)]"
    if ($file.Text.Contains($heading)) {
        Write-Host "  CHANGELOG.md already has $heading" -ForegroundColor Gray
        return
    }

    $nl = $file.Newline
    $unreleased = "## [Unreleased]$nl"
    $index = $file.Text.IndexOf($unreleased)
    if ($index -lt 0) {
        throw "CHANGELOG.md: '## [Unreleased]' heading not found."
    }

    # Entries collected under [Unreleased] now belong to this release; [Unreleased] stays empty.
    $text = $file.Text.Insert($index + $unreleased.Length, "$nl$heading - TBD$nl")
    Write-TextFile $changelogPath $text $file.HasBom
    Write-Host "  Updated CHANGELOG.md ($heading - TBD)" -ForegroundColor Gray
}

$actions = @(@($IncrementMajor, $IncrementMinor, $IncrementPatch, $Final) | Where-Object { $_.IsPresent })
if ($actions.Count -gt 1) {
    throw "Use only one of -IncrementMajor, -IncrementMinor, -IncrementPatch or -Final."
}
if ($Final -and $PreRelease) {
    throw "-Final cannot be combined with -PreRelease."
}
if ($actions.Count -eq 0 -and -not $PreRelease) {
    throw "Nothing to do: pass -PreRelease, -IncrementPatch, -IncrementMinor, -IncrementMajor or -Final."
}

Push-Location $ProjectRoot

try {
    if (-not (Test-Path $VersionFilePath)) {
        throw "Missing $VersionFilePath"
    }

    $versionText = Read-TextFile $VersionFilePath
    $versionData = $versionText.Text | ConvertFrom-Json
    if (-not $versionData.PSObject.Properties['git'] -or -not $versionData.git) {
        Set-JsonProperty $versionData 'git' ([pscustomobject]@{})
    }

    $previousTag = $versionData.git.PSObject.Properties['intendedTag'] ? $versionData.git.intendedTag : $null
    $currentPreRelease = $versionData.PSObject.Properties['preRelease'] ? $versionData.preRelease : $null
    $build = [int]$versionData.build

    if ($IncrementMajor -or $IncrementMinor -or $IncrementPatch) {
        if ($IncrementMajor) {
            $versionData.major = [int]$versionData.major + 1
            $versionData.minor = 0
            $versionData.patch = 0
        } elseif ($IncrementMinor) {
            $versionData.minor = [int]$versionData.minor + 1
            $versionData.patch = 0
        } else {
            $versionData.patch = [int]$versionData.patch + 1
        }
        $build = 1
        $newPreRelease = $PreRelease ? "$PreReleaseLabel.1" : $null
    } elseif ($Final) {
        if (-not $currentPreRelease) {
            throw "-Final requires a current prerelease (version is already final: $($versionData.fullVersion))."
        }
        $build++
        $newPreRelease = $null
    } else {
        if (-not $currentPreRelease) {
            throw "Current version $($versionData.fullVersion) is final; combine -PreRelease with -IncrementPatch, -IncrementMinor or -IncrementMajor."
        }
        $match = [regex]::Match($currentPreRelease, '^([a-z]+)\.(\d+)$')
        if ($match.Success -and $match.Groups[1].Value -eq $PreReleaseLabel) {
            $newPreRelease = "$PreReleaseLabel.$([int]$match.Groups[2].Value + 1)"
        } else {
            $newPreRelease = "$PreReleaseLabel.1"
        }
        $build++
    }

    $baseVersion = "$($versionData.major).$($versionData.minor).$($versionData.patch)"
    $fullVersion = $baseVersion
    $displayVersion = $baseVersion
    if ($newPreRelease) {
        $parts = $newPreRelease.Split('.')
        $fullVersion += "-$newPreRelease"
        $displayVersion += " $(Get-PreReleaseDisplayName $parts[0]) $($parts[1])"
    }

    # lastTag: the previous intended tag once it exists, otherwise the latest reachable tag.
    $lastTag = $null
    if ($previousTag) {
        git rev-parse -q --verify "refs/tags/$previousTag" *> $null
        if ($LASTEXITCODE -eq 0) { $lastTag = $previousTag }
    }
    if (-not $lastTag) {
        $described = git describe --tags --abbrev=0 2>$null
        if ($LASTEXITCODE -eq 0 -and $described) { $lastTag = $described }
    }
    if (-not $lastTag -and $versionData.git.PSObject.Properties['lastTag']) {
        $lastTag = $versionData.git.lastTag
    }

    if (-not $Branch) {
        $Branch = git branch --show-current 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $Branch) { $Branch = "unknown" }
    }

    $versionData.build = $build
    Set-JsonProperty $versionData 'preRelease' $newPreRelease
    Set-JsonProperty $versionData 'fullVersion' $fullVersion
    Set-JsonProperty $versionData 'displayVersion' $displayVersion
    Set-JsonProperty $versionData 'lastUpdated' ([DateTime]::UtcNow.ToString("yyyy-MM-dd") + "T00:00:00Z")
    Set-JsonProperty $versionData.git 'lastTag' $lastTag
    Set-JsonProperty $versionData.git 'intendedTag' "v$fullVersion"
    Set-JsonProperty $versionData.git 'branch' $Branch

    $json = ($versionData | ConvertTo-Json -Depth 10) -replace "\r?\n", $versionText.Newline
    Write-TextFile $VersionFilePath ($json + $versionText.Newline) $versionText.HasBom
    Write-Host "  Updated $VersionFile" -ForegroundColor Gray

    if ($UpdateFiles) {
        Update-EnvyRc -VersionData $versionData
        Update-Changelog -VersionData $versionData
    }

    Write-Host "Version Information:" -ForegroundColor Green
    Write-Host "  Full Version: $fullVersion" -ForegroundColor Cyan
    Write-Host "  Display Version: $displayVersion" -ForegroundColor Cyan
    Write-Host "  Build (release counter): $build" -ForegroundColor Cyan
    Write-Host "  Intended Tag: v$fullVersion" -ForegroundColor Cyan
    Write-Host "  Last Tag: $lastTag" -ForegroundColor Cyan
    Write-Host "  Branch: $Branch" -ForegroundColor Cyan

} finally {
    Pop-Location
}
