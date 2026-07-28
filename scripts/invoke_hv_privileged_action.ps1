param(
    [string]$StatePath = '',
    [string]$RequestPath = '',
    [string]$ResultPath = ''
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$logsDir = Join-Path $root 'logs'
if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $logsDir 'hv_resume.json'
}
if ([string]::IsNullOrWhiteSpace($RequestPath)) {
    $RequestPath = Join-Path $logsDir 'hv_action_request.json'
}
if ([string]::IsNullOrWhiteSpace($ResultPath)) {
    $ResultPath = Join-Path $logsDir 'hv_action_result.json'
}

New-Item -ItemType Directory -Force -Path $logsDir | Out-Null
$logPath = Join-Path $logsDir 'hv_privileged_action.log'
$result = [ordered]@{
    version = 1
    request_id = $null
    action = $null
    status = 'starting'
    message = $null
    started_at = (Get-Date).ToUniversalTime().ToString('o')
    updated_at = $null
    completed_at = $null
    artifact_sha256 = $null
    hv_active_before = $null
    mapped = $false
    diagnostics_sealed = $false
    log_path = $logPath
    steps = @()
}

function Save-Result {
    $result.updated_at = (Get-Date).ToUniversalTime().ToString('o')
    $tmpPath = "$ResultPath.tmp"
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmpPath -Encoding UTF8
    Move-Item -LiteralPath $tmpPath -Destination $ResultPath -Force
}

function Add-Log([string]$Message) {
    $line = '{0} {1}' -f (Get-Date).ToUniversalTime().ToString('o'), $Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    Add-Log "step=$Name command=$FilePath arguments=$($Arguments -join ' ')"
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $nativeOutput = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }

    $outputLines = @($nativeOutput | ForEach-Object { $_.ToString() })
    foreach ($line in $outputLines) {
        Add-Log "[$Name] $line"
    }

    $step = [ordered]@{
        name = $Name
        exit_code = $exitCode
        output = $outputLines
    }
    $result.steps += $step
    Save-Result
    return [pscustomobject]$step
}

try {
    Save-Result

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The privileged action task is not running with an elevated administrator token.'
    }
    if (-not (Test-Path -LiteralPath $StatePath)) {
        throw "Recovery state is missing: $StatePath"
    }
    if (-not (Test-Path -LiteralPath $RequestPath)) {
        throw "Action request is missing: $RequestPath"
    }

    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    $request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    $result.request_id = [string]$request.request_id
    $result.action = [string]$request.action
    Save-Result

    if (-not [bool]$state.pending -or -not [bool]$state.codex_resume_armed) {
        throw 'Recovery is no longer pending or armed.'
    }
    if ([string]$state.phase -notin @('codex_decision', 'needs_review')) {
        throw "Recovery phase does not permit an action: $($state.phase)"
    }
    if ([string]::IsNullOrWhiteSpace($result.request_id)) {
        throw 'Action request_id is missing.'
    }
    if ($result.action -ne 'load_selftest_seal') {
        throw "Unsupported privileged action: $($result.action)"
    }
    if ([string]$request.commit -ne [string]$state.commit) {
        throw 'Action request commit does not match the recovery checkpoint.'
    }

    $requestedAt = [DateTimeOffset]::Parse([string]$request.created_at)
    if ([DateTimeOffset]::UtcNow - $requestedAt.ToUniversalTime() -gt [TimeSpan]::FromMinutes(30)) {
        throw 'Action request is older than 30 minutes.'
    }

    $artifact = [IO.Path]::GetFullPath([string]$state.artifact)
    $requestedArtifact = [IO.Path]::GetFullPath([string]$request.artifact)
    if ($requestedArtifact -ne $artifact) {
        throw 'Action request artifact does not match the recovery checkpoint.'
    }
    foreach ($required in @($artifact, [string]$state.mapper)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Required file is missing: $required"
        }
    }

    $actualHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
    $result.artifact_sha256 = $actualHash
    if ($actualHash -ne [string]$state.artifact_sha256 -or
        $actualHash -ne [string]$request.artifact_sha256) {
        throw 'Driver SHA256 does not match the recovery checkpoint and action request.'
    }

    $ping = Join-Path $root 'tools\cpuid_ping.exe'
    $probe = Join-Path $root 'tools\probe_test.exe'
    foreach ($required in @($ping, $probe)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Required self-test tool is missing: $required"
        }
    }

    $statusBefore = Invoke-Tool -Name 'status_before' -FilePath $ping -Arguments @('--status')
    if ($statusBefore.exit_code -eq 0) {
        $result.hv_active_before = $true
        Add-Log 'HV is already active; skipping mapper and continuing with verification.'
    }
    elseif ($statusBefore.exit_code -eq 2) {
        $result.hv_active_before = $false
        $map = Invoke-Tool -Name 'map_driver' -FilePath ([string]$state.mapper) -Arguments @($artifact)
        if ($map.exit_code -ne 0) {
            throw "Driver mapper failed with exit code $($map.exit_code)."
        }
        $result.mapped = $true
        Save-Result
        Start-Sleep -Milliseconds 750
    }
    else {
        throw "HV status preflight returned unexpected exit code $($statusBefore.exit_code)."
    }

    $pingResult = Invoke-Tool -Name 'cpuid_ping' -FilePath $ping
    if ($pingResult.exit_code -ne 0) {
        throw "CPUID self-test failed with exit code $($pingResult.exit_code)."
    }

    $probeResult = Invoke-Tool -Name 'probe_test' -FilePath $probe
    if ($probeResult.exit_code -ne 0) {
        throw "User-mode probe test failed with exit code $($probeResult.exit_code)."
    }

    $sealResult = Invoke-Tool -Name 'seal_diagnostics' -FilePath $ping -Arguments @('--seal')
    if ($sealResult.exit_code -ne 0) {
        throw "Diagnostic seal failed with exit code $($sealResult.exit_code)."
    }

    $statusAfter = Invoke-Tool -Name 'status_after' -FilePath $ping -Arguments @('--status')
    if ($statusAfter.exit_code -ne 0) {
        throw "Final HV status check failed with exit code $($statusAfter.exit_code)."
    }

    $result.status = 'completed'
    $result.message = 'HV load/self-test/seal action completed.'
    $result.diagnostics_sealed = $true
    $result.completed_at = (Get-Date).ToUniversalTime().ToString('o')
    Save-Result
    Add-Log "request=$($result.request_id) status=completed mapped=$($result.mapped)"
    exit 0
}
catch {
    $result.status = 'failed'
    $result.message = $_.Exception.Message
    $result.completed_at = (Get-Date).ToUniversalTime().ToString('o')
    Save-Result
    Add-Log "request=$($result.request_id) status=failed error=$($result.message)"
    exit 1
}
