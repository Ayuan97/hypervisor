param(
    [string]$TaskName = 'Hypervisor resume after boot'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$resumeScript = Join-Path $PSScriptRoot 'resume_after_boot.ps1'

$action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$resumeScript`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description 'Run the HV checkpoint recovery/self-test after boot.' `
    -Force | Out-Null

Write-Host "[+] Registered scheduled task: $TaskName"
Write-Host "    script: $resumeScript"
