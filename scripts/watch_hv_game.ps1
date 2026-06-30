param(
    [ValidateSet("Watch", "Collect")]
    [string]$Mode = "Watch",
    [int]$IntervalSeconds = 5,
    [int]$DurationSeconds = 0,
    [string]$RunDir = "",
    [string]$GameProcess = "rust",
    [switch]$StartHv
)

$ErrorActionPreference = "Continue"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LogRoot = Join-Path $Root "logs"
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null

function Write-SyncText {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text,
        [switch]$Append
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($Text)
    $mode = [System.IO.FileMode]::Create
    if ($Append) {
        $mode = [System.IO.FileMode]::Append
    }

    $stream = New-Object System.IO.FileStream(
        $Path,
        $mode,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::ReadWrite,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        if ($bytes.Length -gt 0) {
            $stream.Write($bytes, 0, $bytes.Length)
        }
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Append-Log {
    param([string]$Path, [string]$Text)
    Write-SyncText -Path $Path -Text ("[{0}] {1}`r`n" -f (Get-Date).ToString("o"), $Text) -Append
}

function Capture-Text {
    param([string]$Path, [scriptblock]$Block)
    try {
        $text = (& $Block 2>&1 | Out-String)
        Write-SyncText -Path $Path -Text $text
    }
    catch {
        Write-SyncText -Path $Path -Text ("capture failed: {0}`r`n" -f $_)
    }
}

function Invoke-CpuidPing {
    param([string[]]$Args)
    $exe = Join-Path $Root "tools\cpuid_ping.exe"
    if (-not (Test-Path $exe)) {
        return [pscustomobject]@{ Exit = 127; Text = "missing $exe" }
    }

    $text = (& $exe @Args 2>&1 | Out-String).Trim()
    return [pscustomobject]@{ Exit = $LASTEXITCODE; Text = $text }
}

function Escape-Csv {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) {
        return ""
    }
    $s = [string]$Value
    if ($s.Contains('"') -or $s.Contains(",") -or $s.Contains("`r") -or $s.Contains("`n")) {
        return '"' + $s.Replace('"', '""') + '"'
    }
    return $s
}

function Get-DumpInventoryText {
    $items = @()
    if (Test-Path "C:\Windows\MEMORY.DMP") {
        $items += Get-Item "C:\Windows\MEMORY.DMP"
    }
    if (Test-Path "C:\Windows\Minidump") {
        $items += Get-ChildItem "C:\Windows\Minidump" -Filter "*.dmp" -ErrorAction SilentlyContinue
    }
    if (Test-Path "C:\Windows\LiveKernelReports") {
        $items += Get-ChildItem "C:\Windows\LiveKernelReports" -Recurse -Filter "*.dmp" -ErrorAction SilentlyContinue
    }

    if ($items.Count -eq 0) {
        return "no dump files found`r`n"
    }

    return ($items |
        Sort-Object LastWriteTime -Descending |
        Select-Object FullName, Length, LastWriteTime |
        Format-Table -AutoSize |
        Out-String)
}

function Capture-SystemEvents {
    param([string]$Path, [datetime]$StartTime)
    $events = Get-WinEvent -FilterHashtable @{ LogName = "System"; StartTime = $StartTime } -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProviderName -match "BugCheck|Kernel-Power|WHEA|Display|nvlddmkm|amdkmdag|dxgkrnl|Application Popup|volmgr|EventLog|Disk|stornvme|storahci|Ntfs|Service Control Manager|Wininit" -or
            $_.Id -in 1, 14, 18, 26, 41, 51, 55, 57, 129, 153, 157, 161, 4101, 6005, 6006, 6008, 1001
        } |
        Sort-Object TimeCreated -Descending |
        Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, @{n="Message";e={($_.Message -replace "`r?`n", " ")}}

    Write-SyncText -Path $Path -Text ($events | Format-List | Out-String)
}

function Capture-WheaSummary {
    param([string]$Path)
    $rows = Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Microsoft-Windows-WHEA-Logger" } -MaxEvents 8 -ErrorAction SilentlyContinue |
        ForEach-Object {
            [xml]$xml = $_.ToXml()
            $length = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Length" }).InnerText
            $raw = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "RawData" }).InnerText
            $sig = ""
            $severity = ""
            $sectionCount = ""
            if ($raw -and $raw.Length -ge 40) {
                $bytes = New-Object byte[] ($raw.Length / 2)
                for ($i = 0; $i -lt $bytes.Length; $i++) {
                    $bytes[$i] = [Convert]::ToByte($raw.Substring($i * 2, 2), 16)
                }
                $sig = [Text.Encoding]::ASCII.GetString($bytes, 0, 4)
                $sectionCount = [BitConverter]::ToUInt16($bytes, 10)
                $sev = [BitConverter]::ToUInt32($bytes, 12)
                $severity = switch ($sev) { 0 { "Recoverable" } 1 { "Fatal" } 2 { "Corrected" } 3 { "Informational" } default { $sev } }
            }
            [pscustomobject]@{
                TimeCreated = $_.TimeCreated
                RecordId = $_.RecordId
                Length = $length
                Signature = $sig
                Severity = $severity
                SectionCount = $sectionCount
            }
        }

    Write-SyncText -Path $Path -Text ($rows | Format-Table -AutoSize | Out-String)
}

function Capture-Baseline {
    param([string]$Dir)

    $context = [pscustomobject]@{
        Time = (Get-Date).ToString("o")
        Root = $Root
        Computer = $env:COMPUTERNAME
        User = $env:USERNAME
        BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        LogicalProcessors = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
        GameProcess = $GameProcess
    }
    Write-SyncText -Path (Join-Path $Dir "00_context.txt") -Text ($context | Format-List | Out-String)

    $cpuidStatus = Invoke-CpuidPing @("--status")
    Write-SyncText -Path (Join-Path $Dir "01_hv_status_before.log") -Text (($cpuidStatus.Text + "`r`nexit=" + $cpuidStatus.Exit + "`r`n"))
    Write-SyncText -Path (Join-Path $Dir "02_dumps_before.log") -Text (Get-DumpInventoryText)
    Capture-SystemEvents -Path (Join-Path $Dir "03_recent_before_system_events.log") -StartTime ((Get-Date).AddMinutes(-30))
    Capture-WheaSummary -Path (Join-Path $Dir "03_recent_before_whea_summary.log")
    Capture-Text -Path (Join-Path $Dir "04_video_controller.log") { Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, DriverDate, Status, PNPDeviceID | Format-List }
    Capture-Text -Path (Join-Path $Dir "05_bcdedit_current.log") { bcdedit /enum "{current}" }
    Capture-Text -Path (Join-Path $Dir "06_powercfg_a.log") { powercfg /a }
    Capture-Text -Path (Join-Path $Dir "07_loaded_filters.log") { fltmc filters }
    Capture-Text -Path (Join-Path $Dir "08_driverquery.csv") { driverquery /v /fo csv }
    $cpuidFull = Invoke-CpuidPing @()
    Write-SyncText -Path (Join-Path $Dir "09_cpuid_full_before.log") -Text (($cpuidFull.Text + "`r`nexit=" + $cpuidFull.Exit + "`r`n"))
}

function Collect-AfterReboot {
    param([string]$Dir)
    if (-not $Dir) {
        $latestFile = Join-Path $LogRoot "watch_latest.txt"
        if (Test-Path $latestFile) {
            $Dir = (Get-Content $latestFile | Select-Object -First 1).Trim()
        }
    }
    if (-not $Dir -or -not (Test-Path $Dir)) {
        throw "no watch run directory found"
    }

    $collectStamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $stateFile = Join-Path $Dir "state.json"
    $start = (Get-Date).AddHours(-2)
    if (Test-Path $stateFile) {
        try {
            $state = Get-Content $stateFile -Raw | ConvertFrom-Json
            $start = [datetime]$state.startedAt
        }
        catch {}
    }

    Append-Log (Join-Path $Dir "summary.log") ("collect started: " + $collectStamp)
    $status = Invoke-CpuidPing @("--status")
    Write-SyncText -Path (Join-Path $Dir ("collect_{0}_hv_status.log" -f $collectStamp)) -Text (($status.Text + "`r`nexit=" + $status.Exit + "`r`n"))
    Write-SyncText -Path (Join-Path $Dir ("collect_{0}_dumps.log" -f $collectStamp)) -Text (Get-DumpInventoryText)
    Capture-SystemEvents -Path (Join-Path $Dir ("collect_{0}_system_events.log" -f $collectStamp)) -StartTime $start
    Capture-WheaSummary -Path (Join-Path $Dir ("collect_{0}_whea_summary.log" -f $collectStamp))
    Capture-Text -Path (Join-Path $Dir ("collect_{0}_reliability.log" -f $collectStamp)) {
        Get-CimInstance Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeGenerated -ge $start } |
            Sort-Object TimeGenerated -Descending |
            Select-Object TimeGenerated, SourceName, EventIdentifier, Message |
            Format-List
    }
    Append-Log (Join-Path $Dir "summary.log") ("collect finished: " + $collectStamp)
    Write-Host ("[+] collected into " + $Dir)
}

if ($Mode -eq "Collect") {
    Collect-AfterReboot -Dir $RunDir
    exit 0
}

if (-not $RunDir) {
    $RunDir = Join-Path $LogRoot ("watch_" + (Get-Date).ToString("yyyyMMdd_HHmmss"))
}
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
Write-SyncText -Path (Join-Path $LogRoot "watch_latest.txt") -Text ($RunDir + "`r`n")

$state = [pscustomobject]@{
    mode = "Watch"
    runDir = $RunDir
    startedAt = (Get-Date).ToString("o")
    bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")
    intervalSeconds = $IntervalSeconds
    durationSeconds = $DurationSeconds
    gameProcess = $GameProcess
    startHvRequested = [bool]$StartHv
    root = $Root
}
Write-SyncText -Path (Join-Path $RunDir "state.json") -Text (($state | ConvertTo-Json -Depth 4) + "`r`n")
Append-Log (Join-Path $RunDir "summary.log") ("watch run started: " + $RunDir)

if ($StartHv) {
    Capture-Text -Path (Join-Path $RunDir "00_start_hv.log") {
        Push-Location $Root
        try { & (Join-Path $Root "scripts\start_hv.bat") }
        finally { Pop-Location }
    }
}

Capture-Baseline -Dir $RunDir

$heartbeat = Join-Path $RunDir "heartbeat.csv"
Write-SyncText -Path $heartbeat -Text "time,uptime_seconds,hv_exit,hv_status,game_present,game_pids,game_names,available_mb,committed_mb,last_system_record_id`r`n"

$startTime = Get-Date
while ($true) {
    $now = Get-Date
    if ($DurationSeconds -gt 0 -and (($now - $startTime).TotalSeconds -ge $DurationSeconds)) {
        break
    }

    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = [int](($now - $os.LastBootUpTime).TotalSeconds)
    $hv = Invoke-CpuidPing @("--status")
    $pattern = "*" + $GameProcess + "*"
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like $pattern })
    $gamePresent = $procs.Count -gt 0
    $gamePids = ($procs | Select-Object -ExpandProperty Id) -join "|"
    $gameNames = ($procs | Select-Object -ExpandProperty ProcessName -Unique) -join "|"
    $availableMb = [int]($os.FreePhysicalMemory / 1024)
    $committedMb = [int](($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1024)
    $lastRecord = (Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId
    $hvOneLine = (($hv.Text -replace "`r?`n", " | ") -replace "\s+", " ").Trim()

    $row = @(
        $now.ToString("o"),
        $uptime,
        $hv.Exit,
        $hvOneLine,
        $gamePresent,
        $gamePids,
        $gameNames,
        $availableMb,
        $committedMb,
        $lastRecord
    ) | ForEach-Object { Escape-Csv $_ }
    Write-SyncText -Path $heartbeat -Text (($row -join ",") + "`r`n") -Append
    Start-Sleep -Seconds $IntervalSeconds
}

Append-Log (Join-Path $RunDir "summary.log") "watch run stopped normally"
Write-Host ("[+] watch log: " + $RunDir)
