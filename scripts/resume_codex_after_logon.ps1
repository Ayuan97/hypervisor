param(
    [string]$StatePath = ''
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $root 'logs\hv_resume.json'
}

if (-not (Test-Path -LiteralPath $StatePath)) {
    exit 0
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if (-not [bool]$state.pending -or -not [bool]$state.codex_resume_armed) {
    exit 0
}

function Save-State([object]$Value) {
    $tmpPath = "$StatePath.tmp"
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmpPath -Encoding UTF8
    Move-Item -LiteralPath $tmpPath -Destination $StatePath -Force
}

$threadId = [string]$state.codex_thread_id
if ([string]::IsNullOrWhiteSpace($threadId)) {
    throw 'codex_thread_id is missing from the recovery checkpoint.'
}

$state.status = 'ready_for_codex'
$state.phase = 'codex_decision'
$state.boot_started_at = (Get-Date).ToUniversalTime().ToString('o')
$state.action_owner = 'codex'
Save-State $state

$uri = "codex://threads/$threadId"
Start-Process -FilePath 'explorer.exe' -ArgumentList $uri
