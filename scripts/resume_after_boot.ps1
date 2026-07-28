param(
    [string]$StatePath = '',
    [int]$WaitSeconds = 90
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$workspaceRoot = Split-Path -Parent $root
if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $root 'logs\hv_resume.json'
}
$logsDir = Split-Path -Parent $StatePath
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

if (-not (Test-Path -LiteralPath $StatePath)) {
    exit 0
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if (-not [bool]$state.pending) {
    exit 0
}

function Save-State([object]$Value) {
    $tmpPath = "$StatePath.tmp"
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmpPath -Encoding UTF8
    Move-Item -LiteralPath $tmpPath -Destination $StatePath -Force
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logPath = Join-Path $logsDir "hv_resume_$stamp.log"
$state.status = 'boot_check'
$state.phase = 'post_boot_self_test'
$state.boot_started_at = (Get-Date).ToUniversalTime().ToString('o')
$state.last_log = $logPath
$state.error = $null
Save-State $state

Start-Transcript -LiteralPath $logPath -Force | Out-Null
try {
    $ping = Join-Path $root 'tools\cpuid_ping.exe'
    $probe = Join-Path $root 'tools\probe_test.exe'
    $mapper = [string]$state.mapper
    if ([string]::IsNullOrWhiteSpace($mapper)) {
        $mapper = Join-Path $workspaceRoot 'tools\kdmapper\x64\Release\kdmapper_Release.exe'
    }

    Start-Sleep -Seconds 30

    $state.artifact_present = Test-Path -LiteralPath $state.artifact
    $state.mapper_present = Test-Path -LiteralPath $mapper
    $state.ping_present = Test-Path -LiteralPath $ping
    $state.probe_present = Test-Path -LiteralPath $probe
    $state.artifact_hash_ok = $false
    if ($state.artifact_present -and
        -not [string]::IsNullOrWhiteSpace([string]$state.artifact_sha256)) {
        $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $state.artifact).Hash
        $state.artifact_hash_ok = ($actualSha256 -eq [string]$state.artifact_sha256)
        Write-Host "[*] Artifact hash expected=$($state.artifact_sha256) actual=$actualSha256"
    }

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline -and -not $state.ping_present) {
        Start-Sleep -Seconds 5
        $state.ping_present = Test-Path -LiteralPath $ping
    }
    if ($state.ping_present) {
        & $ping --status 2>&1 | Out-Host
        $state.hv_status_code = $LASTEXITCODE
        $state.hv_active = ($state.hv_status_code -eq 0)
    }

    $state.status = 'ready_for_codex'
    $state.phase = 'codex_decision'
    $state.pending = $true
    $state.action_owner = 'codex'
    $state.hv_self_test_completed_at = $null
    Save-State $state
    Write-Host '[+] Boot facts collected; Codex owns the next action decision.'
}
catch {
    $state.status = 'failed'
    $state.phase = 'needs_review'
    $state.pending = $true
    $state.error = $_.Exception.Message
    $state.failed_at = (Get-Date).ToUniversalTime().ToString('o')
    Save-State $state
    Write-Error $_
    exit 1
}
finally {
    Stop-Transcript | Out-Null
}
