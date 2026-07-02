param(
    [ValidateSet("Watch", "Collect")]
    [string]$Mode = "Watch",
    [int]$IntervalSeconds = 1,
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

function Decode-CperGuid {
    param([byte[]]$Bytes, [int]$Offset)
    $g = New-Object byte[] 16
    [Array]::Copy($Bytes, $Offset, $g, 0, 16)
    return ([Guid]::new($g)).ToString()
}

function Capture-WheaDecoded {
    param([string]$Path, [datetime]$StartTime)
    $rows = Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Microsoft-Windows-WHEA-Logger"; StartTime = $StartTime } -ErrorAction SilentlyContinue |
        Select-Object -First 12 |
        ForEach-Object {
            [xml]$xml = $_.ToXml()
            $raw = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "RawData" }).InnerText
            if (-not $raw -or $raw.Length -lt 256) {
                [pscustomobject]@{ TimeCreated=$_.TimeCreated; Id=$_.Id; Signature=""; NotifyType=""; Severity=""; Flags=""; Sections="" }
                return
            }

            $bytes = New-Object byte[] ($raw.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bytes[$i] = [Convert]::ToByte($raw.Substring($i * 2, 2), 16)
            }

            $sig = [Text.Encoding]::ASCII.GetString($bytes, 0, 4)
            $sectionCount = [BitConverter]::ToUInt16($bytes, 10)
            $sevRaw = [BitConverter]::ToUInt32($bytes, 12)
            $severity = switch ($sevRaw) { 0 { "Recoverable" } 1 { "Fatal" } 2 { "Corrected" } 3 { "Informational" } default { $sevRaw } }
            $notifyType = Decode-CperGuid -Bytes $bytes -Offset 80
            $flags = "0x{0:x8}" -f [BitConverter]::ToUInt32($bytes, 104)

            $sections = @()
            for ($n = 0; $n -lt $sectionCount; $n++) {
                $o = 128 + 72 * $n
                if ($o + 64 -ge $bytes.Length) { break }
                $sectionType = Decode-CperGuid -Bytes $bytes -Offset ($o + 16)
                $sectionSeverity = [BitConverter]::ToUInt32($bytes, $o + 48)
                $sections += ("{0}:{1}" -f $sectionType, $sectionSeverity)
            }

            [pscustomobject]@{
                TimeCreated = $_.TimeCreated
                Id = $_.Id
                Signature = $sig
                NotifyType = $notifyType
                Severity = $severity
                Flags = $flags
                Sections = ($sections -join "|")
            }
        }

    Write-SyncText -Path $Path -Text ($rows | Format-Table -AutoSize | Out-String)
}

function Resolve-RunDir {
    param([string]$Dir)
    if ($Dir) {
        return $Dir
    }
    $latest = Join-Path $LogRoot "breadcrumb_latest.txt"
    if (Test-Path $latest) {
        return (Get-Content $latest | Select-Object -First 1).Trim()
    }
    throw "no breadcrumb run directory found"
}

if ($Mode -eq "Collect") {
    $RunDir = Resolve-RunDir -Dir $RunDir
    if (-not (Test-Path $RunDir)) {
        throw "run directory not found: $RunDir"
    }

    $stateFile = Join-Path $RunDir "state.json"
    $start = (Get-Date).AddHours(-2)
    if (Test-Path $stateFile) {
        try {
            $state = Get-Content $stateFile -Raw | ConvertFrom-Json
            $start = [datetime]$state.startedAt
        }
        catch {}
    }

    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    Append-Log (Join-Path $RunDir "summary.log") "collect started"
    Capture-Text -Path (Join-Path $RunDir "collect_${stamp}_hv_status.log") { & (Join-Path $Root "tools\cpuid_ping.exe") --status }
    Write-SyncText -Path (Join-Path $RunDir "collect_${stamp}_dumps.log") -Text (Get-DumpInventoryText)
    Capture-SystemEvents -Path (Join-Path $RunDir "collect_${stamp}_system_events.log") -StartTime $start
    Capture-WheaDecoded -Path (Join-Path $RunDir "collect_${stamp}_whea_decoded.log") -StartTime $start
    Capture-Text -Path (Join-Path $RunDir "collect_${stamp}_reliability.log") {
        Get-CimInstance Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeGenerated -ge $start } |
            Sort-Object TimeGenerated -Descending |
            Select-Object TimeGenerated, SourceName, EventIdentifier, Message |
            Format-List
    }
    Append-Log (Join-Path $RunDir "summary.log") "collect finished"
    Write-Host "[+] collected: $RunDir"
    exit 0
}

if (-not $RunDir) {
    $RunDir = Join-Path $LogRoot ("breadcrumb_" + (Get-Date).ToString("yyyyMMdd_HHmmss"))
}
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
Write-SyncText -Path (Join-Path $LogRoot "breadcrumb_latest.txt") -Text ($RunDir + "`r`n")

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
Append-Log (Join-Path $RunDir "summary.log") "watch started"

Capture-Text -Path (Join-Path $RunDir "00_context.log") {
    [pscustomobject]@{
        Time = (Get-Date).ToString("o")
        BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        LogicalProcessors = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
        GameProcess = $GameProcess
        Root = $Root
    } | Format-List
}
Capture-Text -Path (Join-Path $RunDir "01_hv_status_before.log") { & (Join-Path $Root "tools\cpuid_ping.exe") --status }
Write-SyncText -Path (Join-Path $RunDir "02_dumps_before.log") -Text (Get-DumpInventoryText)
Capture-SystemEvents -Path (Join-Path $RunDir "03_system_before.log") -StartTime ((Get-Date).AddMinutes(-30))
Capture-WheaDecoded -Path (Join-Path $RunDir "04_whea_before.log") -StartTime ((Get-Date).AddHours(-2))

if ($StartHv) {
    Append-Log (Join-Path $RunDir "summary.log") "starting HV with HV_NO_SEAL=1"
    $env:HV_NO_SEAL = "1"
    Capture-Text -Path (Join-Path $RunDir "05_start_hv.log") {
        Push-Location $Root
        try {
            $start = Join-Path $Root "scripts\start_hv_client.bat"
            & cmd.exe /c ("echo.| `"{0}`"" -f $start)
        }
        finally { Pop-Location }
    }
}

$exe = Join-Path $Root "tools\hv_breadcrumb.exe"
if (-not (Test-Path $exe)) {
    throw "missing $exe"
}

$csv = Join-Path $RunDir "hv_breadcrumb.csv"
$intervalMs = [Math]::Max(1, $IntervalSeconds) * 1000
$args = @("--out", $csv, "--interval-ms", $intervalMs.ToString(), "--cpus", "256")
if ($DurationSeconds -gt 0) {
    $args += @("--duration-seconds", $DurationSeconds.ToString())
}

Append-Log (Join-Path $RunDir "summary.log") "breadcrumb sampler starting"
Write-Host "[*] breadcrumb log: $csv"
Write-Host "[*] start the game now; after reboot run: .\scripts\watch_hv_breadcrumbs.bat -Mode Collect"
& $exe @args
$exitCode = $LASTEXITCODE
Append-Log (Join-Path $RunDir "summary.log") "breadcrumb sampler exited code=$exitCode"
exit $exitCode
