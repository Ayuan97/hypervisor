# UDP HV Monitor - continuously reads breadcrumbs via CPUID and streams to Mac
# Run: powershell -NoProfile -File D:\hello\code\hypervisor\tools\udp_hv_monitor.ps1
param(
    [string]$RemoteIP = "100.91.62.12",
    [int]$Port = 9999,
    [int]$IntervalMs = 150
)

$ErrorActionPreference = "SilentlyContinue"
$udp = New-Object System.Net.Sockets.UdpClient
$endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($RemoteIP), $Port)

function Send-Msg($msg) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
    [void]$udp.Send($bytes, $bytes.Length, $endpoint)
}

$pingExe = "D:\hello\code\hypervisor\tools\cpuid_ping.exe"

Send-Msg "=== HV UDP Monitor START $(Get-Date -Format 'HH:mm:ss.fff') ==="

$seq = 0
$lastTotal = 0
$lastEpt = 0
$lastGp = 0

while ($true) {
    $seq++
    $ts = Get-Date -Format 'HH:mm:ss.fff'

    # Quick status - captures exit counters and breadcrumbs
    $raw = & $pingExe 2>&1 | Out-String

    # Extract key metrics
    $total = if ($raw -match 'Total\s+=\s+(\d+)') { $Matches[1] } else { "?" }
    $cpuid = if ($raw -match 'CPUID\s+=\s+(\d+)') { $Matches[1] } else { "?" }
    $lastExit = if ($raw -match 'LastExitReason\s+=\s+(0x[0-9a-f]+)') { $Matches[1] } else { "?" }
    $tscOff = if ($raw -match 'TSC_OFFSET\s+=\s+(0x[0-9a-f]+)') { $Matches[1] } else { "?" }
    $stage = if ($raw -match 'BOOT_STAGE\s+=\s+(\d+)') { $Matches[1] } else { "?" }
    $eptViol = if ($raw -match 'EPT.*violation') { "EPT!" } else { "" }
    $gpCount = if ($raw -match 'Host #GP\s+=\s+count=(\d+)') { $Matches[1] } else { "0" }
    $mcCount = if ($raw -match 'Host #MC\s+=\s+count=(\d+)') { $Matches[1] } else { "0" }
    $pfCount = if ($raw -match 'Host #PF\s+=\s+count=(\d+)') { $Matches[1] } else { "0" }

    $deltaTotal = [int64]$total - $lastTotal
    $msg = "[$ts #$seq] exits=$total(+$deltaTotal) cpuid=$cpuid last=$lastExit tsc=$tscOff stage=$stage gp=$gpCount mc=$mcCount pf=$pfCount"

    Send-Msg $msg
    $lastTotal = [int64]$total

    Start-Sleep -Milliseconds $IntervalMs
}
