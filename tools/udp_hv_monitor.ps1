# UDP HV Monitor - continuously reads counters via CPUID and streams to Mac
# Run: powershell -NoProfile -File D:\hello\code\hypervisor\tools\udp_hv_monitor.ps1
# High-freq: powershell -NoProfile -File ... -IntervalMs 50
param(
    [string]$RemoteIP = "100.91.62.12",
    [int]$Port = 9999,
    [int]$IntervalMs = 100
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

while ($true) {
    $seq++
    $ts = Get-Date -Format 'HH:mm:ss.fff'

    $raw = & $pingExe 2>&1 | Out-String

    $total = if ($raw -match 'Total\s+=\s+(\d+)') { $Matches[1] } else { "?" }
    $cpuid = if ($raw -match 'CPUID\s+=\s+(\d+)') { $Matches[1] } else { "?" }
    $msr = if ($raw -match '^\s+MSR\s+=\s+(\d+)' -or $raw -match '\n\s+MSR\s+=\s+(\d+)') { $Matches[1] } else { "0" }
    $lastExit = if ($raw -match 'LastExitReason\s+=\s+(0x[0-9a-f]+)') { $Matches[1] } else { "?" }
    $gpCount = if ($raw -match 'Host #GP\s+=\s+(\d+)') { $Matches[1] } else { "0" }
    $msrAddr = if ($raw -match 'LastMsrAddr\s+=\s+(0x[0-9a-f]+)') { $Matches[1] } else { "0" }
    $msrGp = if ($raw -match 'MsrGpInject\s+=\s+(\d+)') { $Matches[1] } else { "0" }
    $handlerId = if ($raw -match 'LastHandlerID\s+=\s+(\d+)') { $Matches[1] } else { "?" }
    $handlerDet = if ($raw -match 'LastHandlerDet\s+=\s+(0x[0-9a-f]+)') { $Matches[1] } else { "0" }
    $vmxInstr = if ($raw -match 'VMX Instr\s+=\s+(\d+)') { $Matches[1] } else { "0" }
    $pfCount = if ($raw -match 'Host #PF\s+=\s+(\d+)') { $Matches[1] } else { "0" }
    $mcCount = if ($raw -match 'Host #MC\s+=\s+(\d+)') { $Matches[1] } else { "0" }
    $rdtsc = if ($raw -match 'RDTSC\s+=\s+(\d+)') { $Matches[1] } else { "0" }

    $deltaTotal = [int64]$total - $lastTotal
    $msg = "[$ts #$seq] exits=$total(+$deltaTotal) hid=$handlerId det=$handlerDet msr=$msr/$msrAddr gp=$msrGp vmx=$vmxInstr rdtsc=$rdtsc hostGP=$gpCount PF=$pfCount MC=$mcCount last=$lastExit"

    Send-Msg $msg
    $lastTotal = [int64]$total

    Start-Sleep -Milliseconds $IntervalMs
}
