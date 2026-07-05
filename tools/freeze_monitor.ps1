$ping = "D:\hello\code\hypervisor\tools\cpuid_ping.exe"
$log  = "D:\hello\code\hypervisor\logs\freeze_monitor.log"

"======== freeze_monitor started $(Get-Date -f 'yyyy-MM-dd HH:mm:ss') ========" | Out-File $log -Encoding utf8

$poll = 0
while ($true) {
    $poll++
    $ts = Get-Date -f 'HH:mm:ss.fff'
    $out = & $ping 2>&1 | Out-String

    $total   = if ($out -match 'Total\s+=\s+(\d+)')    { $Matches[1] } else { '?' }
    $cpuid   = if ($out -match 'CPUID\s+=\s+(\d+)')    { $Matches[1] } else { '?' }
    $ept     = if ($out -match 'EPT Viol\s+=\s+(\d+)') { $Matches[1] } else { '0' }
    $cr      = if ($out -match 'CR Access\s+=\s+(\d+)') { $Matches[1] } else { '0' }
    $msr     = if ($out -match 'MSR\s+=\s+(\d+)')      { $Matches[1] } else { '0' }
    $vmxi    = if ($out -match 'VMX Instr\s+=\s+(\d+)') { $Matches[1] } else { '0' }
    $other   = if ($out -match 'Other\s+=\s+(\d+)')    { $Matches[1] } else { '0' }
    $hostgp  = if ($out -match 'Host #GP\s+=\s+(\d+)') { $Matches[1] } else { '0' }
    $hostpf  = if ($out -match 'Host #PF\s+=\s+count=(\d+)') { $Matches[1] } else { '0' }
    $lastid  = if ($out -match 'LastHandlerID\s+=\s+(\d+)') { $Matches[1] } else { '?' }
    $lastdet = if ($out -match 'LastHandlerDet\s+=\s+(0x[0-9a-fA-F]+)') { $Matches[1] } else { '?' }
    $lreason = if ($out -match 'LastExitReason\s+=\s+(0x[0-9a-fA-F]+)') { $Matches[1] } else { '?' }
    $ridx    = if ($out -match 'Write index\s+=\s+(\d+)') { $Matches[1] } else { '?' }

    $ring_lines = ($out -split "`n") | Where-Object { $_ -match '^\s+\[\d+\]\s+reason=' }
    $ring_text  = if ($ring_lines) { ($ring_lines | ForEach-Object { $_.Trim() }) -join ' | ' } else { '' }

    $summary = "[$ts] poll=$poll T=$total C=$cpuid EPT=$ept CR=$cr MSR=$msr VMX=$vmxi Other=$other GP=$hostgp PF=$hostpf hid=$lastid det=$lastdet lr=$lreason ri=$ridx"
    if ($ring_text) { $summary += " ring: $ring_text" }

    $summary | Out-File $log -Append -Encoding utf8
    Write-Host $summary

    Start-Sleep -Seconds 2
}
