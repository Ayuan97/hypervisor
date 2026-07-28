param(
    [ValidateSet('load_selftest_seal')]
    [string]$Action = 'load_selftest_seal',
    [string]$TaskName = 'Codex HV privileged action',
    [int]$TimeoutSeconds = 55
)

$ErrorActionPreference = 'Stop'
if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 55) {
    throw 'TimeoutSeconds must be between 1 and 55.'
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$logsDir = Join-Path $root 'logs'
$statePath = Join-Path $logsDir 'hv_resume.json'
$requestPath = Join-Path $logsDir 'hv_action_request.json'
$resultPath = Join-Path $logsDir 'hv_action_result.json'

if (-not (Test-Path -LiteralPath $statePath)) {
    throw "Recovery state is missing: $statePath"
}
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if (-not [bool]$state.pending -or -not [bool]$state.codex_resume_armed) {
    throw 'Recovery is not pending and armed.'
}
if ([string]$state.phase -notin @('codex_decision', 'needs_review')) {
    throw "Recovery phase does not permit an action: $($state.phase)"
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if ([string]$task.Principal.RunLevel -ne 'Highest') {
    throw "Scheduled task '$TaskName' is not configured for highest privileges."
}

$actualHash = (Get-FileHash -LiteralPath ([string]$state.artifact) -Algorithm SHA256).Hash
if ($actualHash -ne [string]$state.artifact_sha256) {
    throw 'Driver SHA256 no longer matches the recovery checkpoint.'
}

$requestId = [Guid]::NewGuid().ToString('N')
$request = [ordered]@{
    version = 1
    request_id = $requestId
    action = $Action
    created_at = (Get-Date).ToUniversalTime().ToString('o')
    commit = [string]$state.commit
    artifact = [string]$state.artifact
    artifact_sha256 = $actualHash
    requested_by = 'codex'
}

if (Test-Path -LiteralPath $resultPath) {
    $archiveStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
    Move-Item -LiteralPath $resultPath `
        -Destination (Join-Path $logsDir "hv_action_result.$archiveStamp.json") -Force
}
$tmpPath = "$requestPath.tmp"
$request | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmpPath -Encoding UTF8
Move-Item -LiteralPath $tmpPath -Destination $requestPath -Force

Start-ScheduledTask -TaskName $TaskName
Write-Host "[+] Requested privileged HV action: $Action"
Write-Host "    request_id: $requestId"

$deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $resultPath) {
        try {
            $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
            if ([string]$result.request_id -eq $requestId -and
                [string]$result.status -in @('completed', 'failed')) {
                $result | ConvertTo-Json -Depth 8
                if ([string]$result.status -eq 'completed') {
                    exit 0
                }
                exit 1
            }
        }
        catch {
            # The elevated worker may be between its atomic temp write and move.
        }
    }
} while ([DateTimeOffset]::UtcNow -lt $deadline)

Write-Host "[!] Action is still running; inspect $resultPath on the next bounded wake."
exit 3
