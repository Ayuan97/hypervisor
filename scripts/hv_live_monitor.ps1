[CmdletBinding()]
param(
    [ValidateRange(100, 60000)]
    [int]$IntervalMs = 1000,
    [ValidateRange(100, 60000)]
    [int]$ProbeTimeoutMs = 700,
    [ValidateRange(0, 2147483)]
    [int]$DurationSeconds = 0,
    [string]$GameProcess = "rust",
    [switch]$ActiveHvProbes,
    [switch]$NoBreadcrumb
)

$ErrorActionPreference = "Continue"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LogRoot = Join-Path $Root "logs"
$RunDir = Join-Path $LogRoot "hv_monitor_live"
$TempDir = Join-Path $RunDir ".tmp"
$CpuidExe = Join-Path $Root "tools\cpuid_ping.exe"
$BreadcrumbExe = Join-Path $Root "tools\hv_breadcrumb.exe"

New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
if (Test-Path -LiteralPath $RunDir) {
    # The live directory is deliberately disposable: every run starts clean.
    Get-ChildItem -LiteralPath $RunDir -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

function Write-SyncText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [switch]$Append
    )

    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    $mode = [System.IO.FileMode]::Create
    if ($Append) { $mode = [System.IO.FileMode]::OpenOrCreate }
    $stream = New-Object System.IO.FileStream(
        $Path, $mode, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::ReadWrite, 4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        if ($Append) { $stream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null }
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
        if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Append-Line {
    param([string]$Path, [string]$Text)
    Write-SyncText -Path $Path -Text ("[{0}] {1}`r`n" -f (Get-Date).ToString("o"), $Text) -Append
}

function Csv-Value {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    $text = [string]$Value
    if ($text.Contains('"') -or $text.Contains(',') -or $text.Contains("`r") -or $text.Contains("`n")) {
        return '"' + $text.Replace('"', '""') + '"'
    }
    return $text
}

function Invoke-Capture {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [int]$TimeoutMs = 1000
    )

    $outPath = Join-Path $TempDir "cpuid.out"
    $errPath = Join-Path $TempDir "cpuid.err"
    if (-not (Test-Path -LiteralPath $Exe)) {
        return [pscustomobject]@{ Exit = 127; TimedOut = $false; ElapsedMs = 0; Text = "missing executable: $Exe" }
    }

    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $startParams = @{
            FilePath = $Exe
            WorkingDirectory = $Root
            RedirectStandardOutput = $outPath
            RedirectStandardError = $errPath
            WindowStyle = "Hidden"
            PassThru = $true
        }
        if ($Arguments -and $Arguments.Count -gt 0) { $startParams.ArgumentList = $Arguments }
        $proc = Start-Process @startParams
        $finished = $proc.WaitForExit($TimeoutMs)
        if (-not $finished) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            $proc.WaitForExit(250)
        }
        $watch.Stop()
        $stdout = if (Test-Path $outPath) { [IO.File]::ReadAllText($outPath) } else { "" }
        $stderr = if (Test-Path $errPath) { [IO.File]::ReadAllText($errPath) } else { "" }
        $text = ($stdout + $stderr).Trim()
        $exit = 124
        if ($finished) {
            try { $proc.Refresh(); $exit = [int]$proc.ExitCode } catch { $exit = 1 }
        }
        return [pscustomobject]@{
            Exit = $exit
            TimedOut = (-not $finished)
            ElapsedMs = [int]$watch.ElapsedMilliseconds
            Text = $text
        }
    }
    catch {
        $watch.Stop()
        return [pscustomobject]@{ Exit = 126; TimedOut = $false; ElapsedMs = [int]$watch.ElapsedMilliseconds; Text = $_.Exception.Message }
    }
}

function Get-Metric {
    param([string]$Text, [string]$Pattern, [string]$Default = "")
    $match = [regex]::Match($Text, $Pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($match.Success) { return $match.Groups[1].Value }
    return $Default
}

function Write-JsonLine {
    param([string]$Path, [object]$Value)
    Write-SyncText -Path $Path -Text (($Value | ConvertTo-Json -Compress -Depth 8) + "`r`n") -Append
}

$EventWatermarks = @{}
$EventLogs = @("System", "Application")
function Initialize-EventWatermarks {
    foreach ($logName in $EventLogs) {
        $last = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction SilentlyContinue
        $EventWatermarks[$logName] = if ($last) { [int64]$last.RecordId } else { 0 }
    }
}

function Capture-NewEvents {
    $path = Join-Path $RunDir "windows_events.jsonl"
    foreach ($logName in $EventLogs) {
        $events = @(Get-WinEvent -LogName $logName -MaxEvents 256 -ErrorAction SilentlyContinue |
            Where-Object { [int64]$_.RecordId -gt [int64]$EventWatermarks[$logName] } |
            Sort-Object RecordId)
        foreach ($event in $events) {
            $message = ""
            try { $message = [string]$event.Message } catch { $message = "<message unavailable>" }
            Write-JsonLine -Path $path -Value ([pscustomobject]@{
                capturedAt = (Get-Date).ToString("o")
                log = $logName
                timeCreated = if ($event.TimeCreated) { $event.TimeCreated.ToString("o") } else { "" }
                recordId = [int64]$event.RecordId
                id = [int]$event.Id
                provider = [string]$event.ProviderName
                level = [string]$event.LevelDisplayName
                task = [string]$event.TaskDisplayName
                message = ($message -replace "`r?`n", " ")
            })
            $EventWatermarks[$logName] = [int64]$event.RecordId
        }
    }
}

function Get-GameSnapshot {
    $pattern = $GameProcess + "*"
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like $pattern })
    return [pscustomobject]@{
        Present = ($procs.Count -gt 0)
        Pids = (($procs | Select-Object -ExpandProperty Id) -join "|")
        Names = (($procs | Select-Object -ExpandProperty ProcessName -Unique) -join "|")
    }
}

function Get-OsSnapshot {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os) { return [pscustomobject]@{ Uptime = ""; AvailableMb = ""; CommittedMb = "" } }
    $now = Get-Date
    return [pscustomobject]@{
        Uptime = [int](($now - $os.LastBootUpTime).TotalSeconds)
        AvailableMb = [int]($os.FreePhysicalMemory / 1024)
        CommittedMb = [int](($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1024)
    }
}

$cpuCount = 64
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($computer -and $computer.NumberOfLogicalProcessors) {
    $cpuCount = [Math]::Min(256, [int]$computer.NumberOfLogicalProcessors)
}
$startedAt = Get-Date
$statePath = Join-Path $RunDir "state.json"
$contextPath = Join-Path $RunDir "context.json"

Write-SyncText -Path $contextPath -Text (([pscustomobject]@{
    startedAt = $startedAt.ToString("o")
    computer = $env:COMPUTERNAME
    user = $env:USERNAME
    root = $Root
    intervalMs = $IntervalMs
    probeTimeoutMs = $ProbeTimeoutMs
    durationSeconds = $DurationSeconds
    gameProcess = $GameProcess
    logicalProcessors = $cpuCount
    cpuidExecutable = $CpuidExe
    breadcrumbExecutable = $BreadcrumbExe
    activeHvProbes = [bool]$ActiveHvProbes
    kernelLog = "C:\hv_diag_live.log"
    note = if ($ActiveHvProbes) {
        "Active mode: cpuid_ping and optional hv_breadcrumb generate diagnostic VM-exits."
    } else {
        "Passive local mode: no CPUID/breadcrumb HV queries; diagnostic HV telemetry is in C:\hv_diag_live.log."
    }
} | ConvertTo-Json -Depth 5) + "`r`n")
Initialize-EventWatermarks

$heartbeatPath = Join-Path $RunDir "heartbeat.csv"
$header = "time,sample,uptime_seconds,cpuid_exit,cpuid_timeout,cpuid_elapsed_ms,hv_total,cpuid,external_interrupt,exception,ept_violation,ept_misconfig,cr_access,msr,xsetbv,other,host_gp,host_nmi,host_mc,host_pf,last_exit_reason,last_handler_id,last_handler_detail,vmx_instr,preempt_timer,boot_stage,game_present,game_pids,game_names,available_mb,committed_mb,last_system_record_id`r`n"
Write-SyncText -Path $heartbeatPath -Text $header
$cpuidStatusInitial = ""
if (-not $ActiveHvProbes) {
    $cpuidStatusInitial = "Passive mode: no CPUID diagnostic probes were executed.`r`n"
}
Write-SyncText -Path (Join-Path $RunDir "cpuid_status.log") -Text $cpuidStatusInitial
Write-SyncText -Path (Join-Path $RunDir "monitor.log") -Text ""
Append-Line -Path (Join-Path $RunDir "monitor.log") -Text (
    "monitor started; previous live directory was cleared; active_hv_probes={0}" -f [bool]$ActiveHvProbes
)

$sampler = $null
try {
    if ($ActiveHvProbes -and -not $NoBreadcrumb -and (Test-Path -LiteralPath $BreadcrumbExe)) {
        $breadcrumbPath = Join-Path $RunDir "hv_breadcrumb.csv"
        $samplerOut = Join-Path $RunDir "breadcrumb.stdout.log"
        $samplerErr = Join-Path $RunDir "breadcrumb.stderr.log"
        $samplerArgs = @("--out", $breadcrumbPath, "--interval-ms", $IntervalMs.ToString(), "--cpus", $cpuCount.ToString(), "--include-idle")
        $sampler = Start-Process -FilePath $BreadcrumbExe -ArgumentList $samplerArgs -WorkingDirectory $Root `
            -RedirectStandardOutput $samplerOut -RedirectStandardError $samplerErr `
            -WindowStyle Hidden -PassThru
        Append-Line -Path (Join-Path $RunDir "monitor.log") -Text ("breadcrumb sampler started pid={0} cpus={1}" -f $sampler.Id, $cpuCount)
    }
    elseif ($ActiveHvProbes -and -not $NoBreadcrumb) {
        Append-Line -Path (Join-Path $RunDir "monitor.log") -Text ("breadcrumb sampler unavailable: {0}" -f $BreadcrumbExe)
    }

    $sample = 0
    $lastSystemRecord = 0
    while ($true) {
        $loopStart = Get-Date
        if ($DurationSeconds -gt 0 -and (($loopStart - $startedAt).TotalSeconds -ge $DurationSeconds)) { break }
        $sample++

        if ($ActiveHvProbes) {
            $capture = Invoke-Capture -Exe $CpuidExe -TimeoutMs $ProbeTimeoutMs
            Write-SyncText -Path (Join-Path $RunDir "cpuid_status.log") -Text (
                "=== sample={0} captured={1} exit={2} timeout={3} elapsed_ms={4} ===`r`n{5}`r`n`r`n" -f
                $sample, (Get-Date).ToString("o"), $capture.Exit, $capture.TimedOut, $capture.ElapsedMs, $capture.Text
            ) -Append
        }
        else {
            $capture = [pscustomobject]@{ Exit = ""; TimedOut = ""; ElapsedMs = ""; Text = "" }
        }
        Capture-NewEvents

        $os = Get-OsSnapshot
        $game = Get-GameSnapshot
        $lastRecordEvent = Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($lastRecordEvent) { $lastSystemRecord = [int64]$lastRecordEvent.RecordId }
        $text = $capture.Text
        $fields = @(
            (Get-Date).ToString("o"), $sample, $os.Uptime, $capture.Exit,
            $capture.TimedOut, $capture.ElapsedMs,
            (Get-Metric $text 'Total\s+=\s+(\d+)'),
            (Get-Metric $text 'CPUID\s+=\s+(\d+)'),
            (Get-Metric $text 'External Interrupt\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'Exception\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'EPT[_ ]V(?:iolation)?\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'EPT[_ ]Misconfig\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'CR\s*=\s*(\d+)' '0'),
            (Get-Metric $text '(?m)^\s*MSR\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'XSETBV\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'Other\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'Host #GP\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'Host NMI\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'Host #MC\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'Host #PF\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'LastExitReason\s+=\s+(0x[0-9a-f]+)' ''),
            (Get-Metric $text 'LastHandlerID\s+=\s+(\d+)' ''),
            (Get-Metric $text 'LastHandlerDet\s+=\s+(0x[0-9a-f]+)' ''),
            (Get-Metric $text 'VMX Instr\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'Preempt Timer\s+=\s+(\d+)' '0'),
            (Get-Metric $text 'BOOT_STAGE\s+=\s+(\d+)' ''),
            $game.Present, $game.Pids, $game.Names,
            $os.AvailableMb, $os.CommittedMb, $lastSystemRecord
        ) | ForEach-Object { Csv-Value $_ }
        Write-SyncText -Path $heartbeatPath -Text (($fields -join ",") + "`r`n") -Append

        $samplerState = if ($sampler) { if ($sampler.HasExited) { "exited:$($sampler.ExitCode)" } else { "running:$($sampler.Id)" } } else { "disabled" }
        Write-SyncText -Path $statePath -Text (([pscustomobject]@{
            startedAt = $startedAt.ToString("o")
            lastSampleAt = (Get-Date).ToString("o")
            sample = $sample
            sampler = $samplerState
            activeHvProbes = [bool]$ActiveHvProbes
            cpuidExit = $capture.Exit
            cpuidTimedOut = $capture.TimedOut
            lastSystemRecord = $lastSystemRecord
            runDir = $RunDir
        } | ConvertTo-Json -Depth 5) + "`r`n")

        $elapsed = ((Get-Date) - $loopStart).TotalMilliseconds
        $sleepMs = [Math]::Max(10, $IntervalMs - [int]$elapsed)
        Start-Sleep -Milliseconds $sleepMs
    }
    Append-Line -Path (Join-Path $RunDir "monitor.log") -Text "monitor stopped normally"
}
finally {
    if ($sampler -and -not $sampler.HasExited) {
        Stop-Process -Id $sampler.Id -Force -ErrorAction SilentlyContinue
        Append-Line -Path (Join-Path $RunDir "monitor.log") -Text ("breadcrumb sampler stopped pid={0}" -f $sampler.Id)
    }
    if ($sampler) {
        $state = $null
        if (Test-Path -LiteralPath $statePath) {
            try { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } catch {}
        }
        if (-not $state) { $state = [pscustomobject]@{ runDir = $RunDir } }
        $state | Add-Member -NotePropertyName stoppedAt -NotePropertyValue (Get-Date).ToString("o") -Force
        $state | Add-Member -NotePropertyName sampler -NotePropertyValue "stopped" -Force
        Write-SyncText -Path $statePath -Text (($state | ConvertTo-Json -Depth 5) + "`r`n")
    }
}

Write-Host "[+] HV live monitor logs: $RunDir"
