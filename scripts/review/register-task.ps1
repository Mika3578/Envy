param(
	[Parameter(Mandatory)][string]$Service,
	[Parameter(Mandatory)][string]$Config,
	[Parameter(Mandatory)][string]$Python,
	# Operator-supplied managed PR worktree roots. Never derived solely from the
	# config file, which could be copied from a PR worktree and omit forbidden roots.
	[Parameter(Mandatory)][string[]]$ManagedWorktreeRoots,
	[switch]$EnableCorrections
)
$ErrorActionPreference = 'Stop'
function Convert-HostOwnedPath {
	param([Parameter(Mandatory)][string]$Raw, [Parameter(Mandatory)][string[]]$ForbiddenRoots)
	$full = (Resolve-Path -LiteralPath $Raw).Path
	$fullNorm = $full.TrimEnd('\', '/')
	# For files, also compare the parent directory so a worktree under that
	# parent (e.g. C:\host\pr vs C:\host\service.py) is rejected.
	$candidates = New-Object System.Collections.Generic.List[string]
	[void]$candidates.Add($fullNorm)
	if (Test-Path -LiteralPath $full -PathType Leaf) {
		$parent = Split-Path -LiteralPath $fullNorm -Parent
		if ($parent) { [void]$candidates.Add($parent.TrimEnd('\', '/')) }
	}
	foreach ($root in $ForbiddenRoots) {
		if (-not $root) { continue }
		if (-not (Test-Path -LiteralPath $root)) {
			throw "Managed worktree '$root' does not exist."
		}
		$resolvedRoot = (Resolve-Path -LiteralPath $root).Path
		$rootNorm = $resolvedRoot.TrimEnd('\', '/')
		$sep = [System.IO.Path]::DirectorySeparatorChar
		$alt = [System.IO.Path]::AltDirectorySeparatorChar
		foreach ($candidate in $candidates) {
			if ($candidate.Equals($rootNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
				throw "Scheduled-task path '$full' overlaps managed worktree '$resolvedRoot'."
			}
			# Bidirectional isolation: reject either containment direction.
			if ($candidate.StartsWith($rootNorm + $sep, [System.StringComparison]::OrdinalIgnoreCase) -or
				($alt -ne $sep -and $candidate.StartsWith($rootNorm + $alt, [System.StringComparison]::OrdinalIgnoreCase)) -or
				$rootNorm.StartsWith($candidate + $sep, [System.StringComparison]::OrdinalIgnoreCase) -or
				($alt -ne $sep -and $rootNorm.StartsWith($candidate + $alt, [System.StringComparison]::OrdinalIgnoreCase))) {
				throw "Scheduled-task path '$full' overlaps managed worktree '$resolvedRoot'."
			}
		}
	}
	return $full
}
if (-not $ManagedWorktreeRoots -or $ManagedWorktreeRoots.Count -lt 1) {
	throw 'ManagedWorktreeRoots is required and must list every managed PR worktree root.'
}
# Validate against operator-supplied roots before trusting any config contents.
$taskConfig = Convert-HostOwnedPath -Raw $Config -ForbiddenRoots $ManagedWorktreeRoots
$taskService = Convert-HostOwnedPath -Raw $Service -ForbiddenRoots $ManagedWorktreeRoots
$taskPython = Convert-HostOwnedPath -Raw $Python -ForbiddenRoots $ManagedWorktreeRoots
$configObject = Get-Content -LiteralPath $taskConfig -Raw | ConvertFrom-Json
$forbidden = @($ManagedWorktreeRoots)
foreach ($entry in @($configObject.prs)) {
	if ($entry.worktree) { $forbidden += [string]$entry.worktree }
}
# Re-validate against the union of operator roots and declared worktrees.
$taskService = Convert-HostOwnedPath -Raw $taskService -ForbiddenRoots $forbidden
$taskPython = Convert-HostOwnedPath -Raw $taskPython -ForbiddenRoots $forbidden
$taskConfig = Convert-HostOwnedPath -Raw $taskConfig -ForbiddenRoots $forbidden
foreach ($taskPath in @($taskService, $taskConfig, $taskPython)) {
	if ($taskPath.Contains('"')) { throw 'Task paths cannot contain quote characters.' }
}
# Host configuration remains authoritative; enabling the task cannot override it.
$taskArguments = '"' + $taskService + '" --config "' + $taskConfig + '"'
if (-not $EnableCorrections) { $taskArguments += ' --observe' }
$taskAction = New-ScheduledTaskAction -Execute $taskPython -Argument $taskArguments
# -RepetitionInterval requires -RepetitionDuration. MaxValue is rejected on Windows
# 10/11 hosts; a long finite duration keeps the five-minute cadence effectively indefinite.
$taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
	-RepetitionInterval (New-TimeSpan -Minutes 5) `
	-RepetitionDuration (New-TimeSpan -Days 3650)
$taskSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Days 7)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$taskDefinition = New-ScheduledTask -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description 'Reconcile Envy review feedback; no approval or merge.'
# Refuse to replace another operator-owned task silently.
if (Get-ScheduledTask -TaskName 'Envy Review Reconciliation' -ErrorAction SilentlyContinue) {
	throw 'The reconciliation task already exists; inspect it before updating.'
}
Register-ScheduledTask -TaskName 'Envy Review Reconciliation' -InputObject $taskDefinition | Out-Null
Get-ScheduledTask -TaskName 'Envy Review Reconciliation'
