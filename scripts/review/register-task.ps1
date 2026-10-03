param(
    [Parameter(Mandatory)][string]$Service,
    [Parameter(Mandatory)][string]$Config,
    [Parameter(Mandatory)][string]$Python,
    [switch]$EnableCorrections
)
$ErrorActionPreference = 'Stop'
function Convert-HostOwnedPath {
    param([Parameter(Mandatory)][string]$Raw, [Parameter(Mandatory)][string[]]$ForbiddenRoots)
    $full = (Resolve-Path -LiteralPath $Raw).Path
    foreach ($root in $ForbiddenRoots) {
        if (-not $root) { continue }
        $resolvedRoot = [System.IO.Path]::GetFullPath($root)
        if ($full.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Scheduled-task path '$full' is inside managed worktree '$resolvedRoot'."
        }
    }
    return $full
}
$taskConfig = (Resolve-Path -LiteralPath $Config).Path
$configObject = Get-Content -LiteralPath $taskConfig -Raw | ConvertFrom-Json
$forbidden = @()
foreach ($entry in @($configObject.prs)) {
    if ($entry.worktree) { $forbidden += [string]$entry.worktree }
}
$taskService = Convert-HostOwnedPath -Raw $Service -ForbiddenRoots $forbidden
$taskPython = Convert-HostOwnedPath -Raw $Python -ForbiddenRoots $forbidden
$taskConfig = Convert-HostOwnedPath -Raw $taskConfig -ForbiddenRoots $forbidden
foreach ($taskPath in @($taskService, $taskConfig, $taskPython)) {
    if ($taskPath.Contains('"')) { throw 'Task paths cannot contain quote characters.' }
}
# Host configuration remains authoritative; enabling the task cannot override it.
$taskArguments = '"' + $taskService + '" --config "' + $taskConfig + '"'
if (-not $EnableCorrections) { $taskArguments += ' --observe' }
$taskAction = New-ScheduledTaskAction -Execute $taskPython -Argument $taskArguments
$taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
$taskSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Days 7)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$taskDefinition = New-ScheduledTask -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description 'Reconcile Envy review feedback; no approval or merge.'
# Refuse to replace another operator-owned task silently.
if (Get-ScheduledTask -TaskName 'Envy Review Reconciliation' -ErrorAction SilentlyContinue) {
    throw 'The reconciliation task already exists; inspect it before updating.'
}
Register-ScheduledTask -TaskName 'Envy Review Reconciliation' -InputObject $taskDefinition | Out-Null
Get-ScheduledTask -TaskName 'Envy Review Reconciliation'
