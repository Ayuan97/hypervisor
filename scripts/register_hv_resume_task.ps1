param(
    [string]$TaskName = 'Codex resume after logon'
)

$ErrorActionPreference = 'Stop'
$codexResumeScript = Join-Path $PSScriptRoot 'resume_codex_after_logon.ps1'

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
    -TaskName $TaskName `
    -Action $codexAction `
    -Trigger $codexTrigger `
    -Principal $codexPrincipal `
    -Description 'Open the pending Codex recovery thread after user logon.' `
    -Force | Out-Null

Write-Host "[+] Registered scheduled task: $TaskName"
Write-Host "    script: $codexResumeScript"
