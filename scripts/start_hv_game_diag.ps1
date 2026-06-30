param(
    [string]$GameProcess = "rust",
    [int]$IntervalSeconds = 1,
    [string]$PtConcealMask = ""
)

$ErrorActionPreference = "Continue"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LogRoot = Join-Path $Root "logs"
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null

$RunDir = Join-Path $LogRoot ("game_diag_" + (Get-Date).ToString("yyyyMMdd_HHmmss"))
$WatchDir = Join-Path $RunDir "watch"
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
New-Item -ItemType Directory -Force -Path $WatchDir | Out-Null
Set-Content -Path (Join-Path $LogRoot "game_diag_latest.txt") -Value $RunDir -Encoding ASCII

function Write-Info($Text) {
    $line = "[{0}] {1}" -f (Get-Date).ToString("o"), $Text
    Add-Content -Path (Join-Path $RunDir "summary.log") -Value $line -Encoding ASCII
    Write-Host $line
}

function Run-Logged($Path, [string[]]$Args, $LogName) {
    $log = Join-Path $RunDir $LogName
    Push-Location $Root
    try {
        & $Path @Args > $log 2>&1
        $exit = $LASTEXITCODE
        Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
        Add-Content -Path $log -Value "exit=$exit" -Encoding ASCII
        return $exit
    }
    finally {
        Pop-Location
    }
}

$context = [pscustomobject]@{
    startedAt = (Get-Date).ToString("o")
    root = $Root
    runDir = $RunDir
    watchDir = $WatchDir
    gameProcess = $GameProcess
    intervalSeconds = $IntervalSeconds
    ptConcealMask = $PtConcealMask
    bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")
}
$context | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $RunDir "context.json") -Encoding ASCII

Write-Info "diag run: $RunDir"

if ($PtConcealMask -ne "" -and @("0", "1", "2", "3", "4", "5", "6", "7") -notcontains $PtConcealMask) {
    Write-Info "invalid PtConcealMask=$PtConcealMask; expected 0..7"
    exit 3
}

$ping = Join-Path $Root "tools\cpuid_ping.exe"
$phys = Join-Path $Root "tools\phys_test.exe"
$watch = Join-Path $Root "scripts\watch_hv_game.ps1"
$startHv = Join-Path $Root "scripts\start_hv.bat"
$buildRelease = Join-Path $Root "scripts\build_release.bat"

if (-not (Test-Path $ping) -or -not (Test-Path $phys) -or -not (Test-Path $watch) -or -not (Test-Path $buildRelease)) {
    Write-Info "missing tool, aborting"
    exit 2
}

$statusText = (& $ping --status 2>&1 | Out-String)
$statusText | Set-Content -Path (Join-Path $RunDir "01_hv_status_before.log") -Encoding ASCII
$alreadyActive = $LASTEXITCODE -eq 0

if ($alreadyActive) {
    Write-Info "HV already active; not remapping"
    if ($PtConcealMask -ne "") {
        Write-Info "PtConcealMask requested but HV is already active; reboot before changing VMCS controls"
    }
} else {
    if ($PtConcealMask -ne "") {
        Write-Info "building release with HV_PT_CONCEAL_MASK=$PtConcealMask"
        $env:HV_PT_CONCEAL_MASK = $PtConcealMask
        $buildExit = Run-Logged $buildRelease @() "00_build_release.log"
        Remove-Item Env:\HV_PT_CONCEAL_MASK -ErrorAction SilentlyContinue
        if ($buildExit -ne 0) {
            Write-Info "build failed for HV_PT_CONCEAL_MASK=$PtConcealMask"
            exit 4
        }
    }
    Write-Info "starting HV with HV_NO_SEAL=1"
    $env:HV_NO_SEAL = "1"
    Run-Logged $startHv @() "02_start_hv.log" | Out-Null
    Remove-Item Env:\HV_NO_SEAL -ErrorAction SilentlyContinue
}

Run-Logged $ping @() "03_cpuid_full_after_start.log" | Out-Null

$monitorStdout = Join-Path $RunDir "monitor_stdout.log"
$monitorStderr = Join-Path $RunDir "monitor_stderr.log"
$monitor = Start-Process -FilePath $phys `
    -ArgumentList "monitor" `
    -WorkingDirectory $RunDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $monitorStdout `
    -RedirectStandardError $monitorStderr `
    -PassThru
Write-Info "phys monitor pid=$($monitor.Id)"

$watchStdout = Join-Path $RunDir "watch_stdout.log"
$watchStderr = Join-Path $RunDir "watch_stderr.log"
$watchArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $watch,
    "-Mode", "Watch",
    "-IntervalSeconds", $IntervalSeconds,
    "-GameProcess", $GameProcess,
    "-RunDir", $WatchDir
)
$watcher = Start-Process -FilePath "powershell.exe" `
    -ArgumentList $watchArgs `
    -WorkingDirectory $Root `
    -WindowStyle Hidden `
    -RedirectStandardOutput $watchStdout `
    -RedirectStandardError $watchStderr `
    -PassThru
Write-Info "watcher pid=$($watcher.Id)"
Write-Info "ready; start the game now"

Write-Host ""
Write-Host "[+] HV/game diagnostics are running."
Write-Host "[+] Log dir: $RunDir"
Write-Host "[+] Start the game now. If the PC reboots, come back and say: continue"
