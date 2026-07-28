param(
    [string]$TaskName = 'Hypervisor resume after boot'
)

$ErrorActionPreference = 'Stop'
$resumeScript = Join-Path $PSScriptRoot 'resume_after_boot.ps1'
$codexResumeScript = Join-Path $PSScriptRoot 'resume_codex_after_logon.ps1'

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

$codexTaskName = 'Codex resume after logon'
$codexUser = "$env:USERDOMAIN\$env:USERNAME"
$codexAction = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$codexResumeScript`""
$codexTrigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$codexPrincipal = New-ScheduledTaskPrincipal `
    -UserId $codexUser `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $codexTaskName `
    -Action $codexAction `
    -Trigger $codexTrigger `
    -Principal $codexPrincipal `
    -Description 'Open the pending Codex recovery thread after user logon.' `
    -Force | Out-Null

Write-Host "[+] Registered scheduled task: $codexTaskName"
Write-Host "    script: $codexResumeScript"
