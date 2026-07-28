param(
    [string]$TaskName = 'Codex resume after logon',
    [string]$PrivilegedTaskName = 'Codex HV privileged action'
)

$ErrorActionPreference = 'Stop'
$codexResumeScript = Join-Path $PSScriptRoot 'resume_codex_after_logon.ps1'
$privilegedActionScript = Join-Path $PSScriptRoot 'invoke_hv_privileged_action.ps1'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator permission is required to register the privileged action task.'
}
foreach ($required in @($codexResumeScript, $privilegedActionScript)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required recovery script is missing: $required"
    }
}

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

$privilegedAction = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$privilegedActionScript`""
$privilegedPrincipal = New-ScheduledTaskPrincipal `
    -UserId $codexUser `
    -LogonType Interactive `
    -RunLevel Highest
$privilegedSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $PrivilegedTaskName `
    -Action $privilegedAction `
    -Principal $privilegedPrincipal `
    -Settings $privilegedSettings `
    -Description 'Run one Codex-requested, checkpoint-validated HV load/self-test/seal action.' `
    -Force | Out-Null

Write-Host "[+] Registered on-demand scheduled task: $PrivilegedTaskName"
Write-Host "    script: $privilegedActionScript"
