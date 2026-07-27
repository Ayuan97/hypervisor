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

    if (-not (Test-Path -LiteralPath $state.artifact)) {
        throw "driver artifact not found: $($state.artifact)"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$state.artifact_sha256)) {
        $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $state.artifact).Hash
        if ($actualSha256 -ne [string]$state.artifact_sha256) {
            throw "driver artifact hash mismatch: expected $($state.artifact_sha256), got $actualSha256"
        }
    }

    Start-Sleep -Seconds 30

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $ping)) {
        Start-Sleep -Seconds 5
    }
    if (-not (Test-Path -LiteralPath $ping)) {
        throw "cpuid_ping.exe not found: $ping"
    }

    function Invoke-PingStatus {
        & $ping --status 2>&1 | Out-Host
        return $LASTEXITCODE
    }

    $statusCode = 2
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $statusCode = Invoke-PingStatus
        if ($statusCode -eq 0) {
            break
        }
        Start-Sleep -Seconds 5
    }
    if ($statusCode -ne 0 -and [bool]$state.auto_load) {
        if (-not (Test-Path -LiteralPath $mapper)) {
            throw "kdmapper not found: $mapper"
        }

        $state.status = 'mapping'
        $state.phase = 'auto_load'
        Save-State $state
        Write-Host "[*] HV inactive; mapping the checkpointed artifact."
        & $mapper $state.artifact 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "kdmapper failed with exit code $LASTEXITCODE"
        }
        Start-Sleep -Seconds 2
        $statusCode = 2
        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            $statusCode = Invoke-PingStatus
            if ($statusCode -eq 0) {
                break
            }
            Start-Sleep -Seconds 2
        }
    }

    if ($statusCode -ne 0) {
        throw 'HV is inactive after boot; automatic mapping was not requested or failed.'
    }

    $state.status = 'self_test'
    $state.phase = 'cpuid_and_probe'
    Save-State $state
    & $ping 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "cpuid_ping self-test failed with exit code $LASTEXITCODE"
    }

    if (Test-Path -LiteralPath $probe) {
        & $probe 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "probe_test failed with exit code $LASTEXITCODE"
        }
    }

    if ([bool]$state.auto_seal) {
        $state.status = 'sealing'
        $state.phase = 'diagnostic_seal'
        Save-State $state
        & $ping --seal 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "diagnostic seal failed with exit code $LASTEXITCODE"
        }
    }

    $state.status = 'completed'
    $state.phase = 'ready_for_codex'
    $state.pending = $false
    $state.completed_at = (Get-Date).ToUniversalTime().ToString('o')
    Save-State $state
    Write-Host '[+] Boot recovery completed; Codex heartbeat can resume the task.'
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
