param(
    [switch]$Restart,
    [int]$DelaySeconds = 10
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$logsDir = Join-Path $root 'logs'
$statePath = Join-Path $logsDir 'hv_resume.json'
$artifact = Join-Path $root 'target\release\matrix.sys'

New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

$commit = (& git -C $root rev-parse HEAD 2>$null)
if (-not $commit) {
    $commit = 'unknown'
}

$state = [ordered]@{
    version = 1
    pending = $true
    status = 'awaiting_boot'
    phase = 'pre_reboot_checkpoint'
    created_at = (Get-Date).ToUniversalTime().ToString('o')
    commit = ([string]$commit).Trim()
    artifact = $artifact
    auto_load = $true
    auto_seal = $true
    last_log = $null
    error = $null
    boot_started_at = $null
    completed_at = $null
    failed_at = $null
}

$tmpPath = "$statePath.tmp"
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmpPath -Encoding UTF8
Move-Item -LiteralPath $tmpPath -Destination $statePath -Force

Write-Host "[+] Wrote reboot checkpoint: $statePath"
Write-Host "    commit: $($state.commit)"
Write-Host "    artifact: $artifact"
Write-Host "    auto-load: $($state.auto_load)"
Write-Host "    auto-seal: $($state.auto_seal)"

if ($Restart) {
    if ($DelaySeconds -lt 5) {
        throw 'DelaySeconds must be at least 5 seconds so the checkpoint can be flushed.'
    }
    Write-Host "[*] Reboot scheduled in $DelaySeconds seconds."
    & shutdown.exe /r /t $DelaySeconds /c 'HV resume checkpoint prepared'
    if ($LASTEXITCODE -ne 0) {
        throw "shutdown.exe failed with exit code $LASTEXITCODE"
    }
}
