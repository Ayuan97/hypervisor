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

$threadId = [string]$state.codex_thread_id
if ([string]::IsNullOrWhiteSpace($threadId)) {
    throw 'codex_thread_id is missing from the recovery checkpoint.'
}

$uri = "codex://threads/$threadId"
Start-Process -FilePath 'explorer.exe' -ArgumentList $uri
