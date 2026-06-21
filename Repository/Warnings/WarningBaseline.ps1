<#
.SYNOPSIS
    Freeze the current compiler-warning debt as a baseline and fail CI only
    on NEW first-party warnings (a "ratchet").

.DESCRIPTION
    The Envy core still emits thousands of /Wall-level warnings. Treating
    warnings as errors wholesale is not yet possible, but we can stop the
    bleeding: capture the accepted set once, then reject any pull request
    that introduces a warning not already in that set.

    A warning is keyed by "<repo-relative-path>|<code>" (e.g.
    "envy/buffer.cpp|C5027"). Line and column numbers are deliberately
    dropped so the baseline does not churn every time code moves.

    Only first-party code is tracked. Warnings coming from outside the
    repository (Windows SDK / MSVC headers), from vendored third-party
    trees under Services/, and from the PluginWizard templates are ignored
    because we do not own that code; it is migrated/handled separately
    (vcpkg, Phase 3).

.PARAMETER Mode
    generate -> (re)write the baseline file from the given log(s).
    check    -> compare the given log(s) against the baseline; exit 1 if any
                new first-party warning is found.

.PARAMETER LogPath
    One or more MSBuild log files containing warning lines. Accepts the
    output of /flp:...;warningsonly as well as a full normal-verbosity log.

.PARAMETER BaselinePath
    Path to the baseline file (default: alongside this script).

.PARAMETER RepoRoot
    Repository root used to make paths relative. Defaults to the git root
    of this script, so it works identically on a dev box and on CI runners
    where the absolute workspace path differs.

.EXAMPLE
    pwsh WarningBaseline.ps1 -Mode generate -LogPath build-x64-Release.warnings.log
.EXAMPLE
    pwsh WarningBaseline.ps1 -Mode check -LogPath build-x64-Release.warnings.log
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('generate', 'check')]
    [string]$Mode,
    [Parameter(Mandatory)][string[]]$LogPath,
    [string]$BaselinePath = (Join-Path $PSScriptRoot 'warnings-baseline.txt'),
    [string]$RepoRoot
)

$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) {
    $RepoRoot = (& git -C $PSScriptRoot rev-parse --show-toplevel 2>$null)
    if (-not $RepoRoot) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path }
}
$RepoRoot = ($RepoRoot -replace '\\', '/').TrimEnd('/').ToLowerInvariant()

# "[N>]<path>(line[,col]): warning Cxxxx: ..."  (compiler warnings with a file)
# The optional "N>" is the MSBuild node/project prefix emitted by parallel
# builds at normal verbosity; strip it so it does not pollute the path.
$rx = [regex]'^\s*(?:\d+>)?\s*(?<path>.+?)\((?<line>\d+)(?:,\d+)?\)\s*:\s*warning\s+(?<code>C\d{3,5})\s*:'

function Get-Entries {
    param([string[]]$Logs)
    $set = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($log in $Logs) {
        if (-not (Test-Path -LiteralPath $log)) {
            Write-Warning "Log not found, skipping: $log"; continue
        }
        foreach ($line in [System.IO.File]::ReadLines((Resolve-Path -LiteralPath $log))) {
            $m = $rx.Match($line)
            if (-not $m.Success) { continue }
            $p = ($m.Groups['path'].Value -replace '\\', '/').Trim().ToLowerInvariant()

            # Make repo-relative; anything that is not under the repo root is
            # external (SDK/MSVC) and is not our concern.
            if ($p.StartsWith($RepoRoot + '/')) {
                $rel = $p.Substring($RepoRoot.Length + 1)
            }
            elseif ($p -match '^[a-z]:/' -or $p.StartsWith('//')) {
                continue  # absolute path outside the repo
            }
            else {
                $rel = $p  # already relative
            }

            # Skip code we do not own / do not gate on.
            if ($rel -like 'services/*') { continue }
            if ($rel -like 'plugins/pluginwizard/*') { continue }

            [void]$set.Add(("{0}|{1}" -f $rel, $m.Groups['code'].Value))
        }
    }
    return $set
}

function Read-Baseline {
    param([string]$Path)
    $set = [System.Collections.Generic.HashSet[string]]::new()
    if (Test-Path -LiteralPath $Path) {
        foreach ($line in [System.IO.File]::ReadLines((Resolve-Path -LiteralPath $Path))) {
            # Entries are already canonical (lower-case path, upper-case code)
            # as written by generate mode; preserve them verbatim so the code
            # casing matches Get-Entries.
            $t = $line.Trim()
            if ($t -and -not $t.StartsWith('#')) { [void]$set.Add($t) }
        }
    }
    return $set
}

$current = Get-Entries -Logs $LogPath
$sorted = @($current) | Sort-Object

if ($Mode -eq 'generate') {
    $header = @(
        '# Envy first-party compiler-warning baseline.',
        '# Format: <repo-relative-path>|<warning-code>  (one per line, sorted).',
        '# Line/column numbers are intentionally omitted to avoid churn.',
        '# Excludes Services/ (vendored) and Plugins/PluginWizard/ (templates).',
        '# Regenerate: pwsh Repository/Warnings/WarningBaseline.ps1 -Mode generate \',
        '#   -LogPath build-x64-Release.warnings.log',
        ('# Entries: {0}' -f $sorted.Count),
        ''
    )
    [System.IO.File]::WriteAllLines($BaselinePath, ($header + $sorted), [System.Text.UTF8Encoding]::new($false))
    Write-Host "Wrote baseline: $BaselinePath ($($sorted.Count) entries)"
    exit 0
}

# check mode
$baseline = Read-Baseline -Path $BaselinePath
if ($baseline.Count -eq 0) {
    Write-Error "Baseline is empty or missing: $BaselinePath"
    exit 2
}

$new = @($sorted | Where-Object { -not $baseline.Contains($_) })
$fixed = @($baseline | Where-Object { -not $current.Contains($_) })

Write-Host "First-party warnings now: $($current.Count)  |  baseline: $($baseline.Count)"
if ($fixed.Count -gt 0) {
    Write-Host "Good news: $($fixed.Count) baselined warning(s) no longer present. Consider regenerating the baseline to ratchet down."
}

if ($new.Count -gt 0) {
    Write-Host ""
    Write-Host "::error::$($new.Count) NEW first-party warning(s) introduced (not in baseline):"
    foreach ($n in ($new | Sort-Object)) { Write-Host "  + $n" }
    exit 1
}

Write-Host "No new first-party warnings. OK."
exit 0
