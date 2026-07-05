$ping = "D:\hello\code\hypervisor\tools\cpuid_ping.exe"
$log  = "D:\hello\code\hypervisor\logs\ring_monitor.log"

"[$(Get-Date -f 'HH:mm:ss.fff')] ring_monitor started" | Out-File $log -Encoding utf8

while ($true) {
    $out = & $ping 2>&1 | Out-String
    $ts  = Get-Date -f 'HH:mm:ss.fff'

    $total = if ($out -match 'Total\s+=\s+(\d+)') { $Matches[1] } else { '?' }
    $other = if ($out -match 'Other\s+=\s+(\d+)') { $Matches[1] } else { '0' }
    $ridx  = if ($out -match 'Write index\s+=\s+(\d+)') { $Matches[1] } else { '?' }

    $ring_lines = ($out -split "`n") | Where-Object { $_ -match '^\s+\[\d\]' }
    $ring_text  = if ($ring_lines) { ($ring_lines -join ' | ').Trim() } else { '(empty)' }

    $line = "[$ts] total=$total other=$other ring_idx=$ridx $ring_text"
    $line | Out-File $log -Append -Encoding utf8
    Write-Host $line

    Start-Sleep -Milliseconds 200
}
