[CmdletBinding()]
param(
    [string]$PortName = "",
    [ValidateSet(9600, 19200, 38400, 57600, 115200)]
    [int]$BaudRate = 115200,
    [ValidateRange(0, 2147483)]
    [int]$DurationSeconds = 0
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RunDir = Join-Path $Root "logs\hv_serial_live"

if ([string]::IsNullOrWhiteSpace($PortName)) {
    $ports = @([IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
    if ($ports.Count -eq 1) {
        $PortName = $ports[0]
    }
    elseif ($ports.Count -eq 0) {
        throw "No serial port was found. Connect the receiver adapter and retry."
    }
    else {
        Write-Host ("Available serial ports: " + ($ports -join ", "))
        $PortName = Read-Host "Receiver port (for example COM3)"
    }
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $RunDir) | Out-Null
if (Test-Path -LiteralPath $RunDir) {
    Get-ChildItem -LiteralPath $RunDir -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

$rawPath = Join-Path $RunDir "hv_serial_raw.log"
$timestampedPath = Join-Path $RunDir "hv_serial_timestamped.log"
$contextPath = Join-Path $RunDir "context.json"
$encoding = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText($contextPath, (([pscustomobject]@{
    startedAt = (Get-Date).ToString("o")
    computer = $env:COMPUTERNAME
    port = $PortName
    baudRate = $BaudRate
    durationSeconds = $DurationSeconds
    rawLog = $rawPath
    timestampedLog = $timestampedPath
} | ConvertTo-Json -Depth 4) + "`r`n"), $encoding)

$serial = New-Object IO.Ports.SerialPort(
    $PortName,
    $BaudRate,
    [IO.Ports.Parity]::None,
    8,
    [IO.Ports.StopBits]::One
)
$serial.Handshake = [IO.Ports.Handshake]::None
$serial.ReadTimeout = 250
$serial.DtrEnable = $false
$serial.RtsEnable = $false

$raw = New-Object IO.FileStream(
    $rawPath,
    [IO.FileMode]::Create,
    [IO.FileAccess]::Write,
    [IO.FileShare]::ReadWrite,
    4096,
    [IO.FileOptions]::WriteThrough
)
$timestamped = New-Object IO.StreamWriter(
    $timestampedPath,
    $false,
    $encoding
)
$timestamped.AutoFlush = $true
$buffer = New-Object byte[] 4096
$pending = ""
$startedAt = Get-Date

try {
    $serial.Open()
    Write-Host "[+] Receiving $PortName at $BaudRate baud"
    Write-Host "[+] Logs: $RunDir"
    Write-Host "[+] Press Ctrl+C to stop"

    while ($DurationSeconds -eq 0 -or ((Get-Date) - $startedAt).TotalSeconds -lt $DurationSeconds) {
        try {
            $available = [Math]::Max(1, [Math]::Min($buffer.Length, $serial.BytesToRead))
            $read = $serial.Read($buffer, 0, $available)
        }
        catch [TimeoutException] {
            continue
        }
        if ($read -le 0) { continue }

        $raw.Write($buffer, 0, $read)
        $raw.Flush($true)
        $pending += [Text.Encoding]::ASCII.GetString($buffer, 0, $read)

        while (($newline = $pending.IndexOf("`n")) -ge 0) {
            $line = $pending.Substring(0, $newline).TrimEnd("`r")
            $pending = $pending.Substring($newline + 1)
            $timestamped.WriteLine("[{0}] {1}" -f (Get-Date).ToString("o"), $line)
            Write-Host $line
        }
        if ($pending.Length -gt 16384) {
            $timestamped.WriteLine("[{0}] <unterminated data> {1}" -f (Get-Date).ToString("o"), $pending)
            $pending = ""
        }
    }
}
finally {
    if ($pending.Length -gt 0) {
        $timestamped.WriteLine("[{0}] <partial> {1}" -f (Get-Date).ToString("o"), $pending)
    }
    if ($serial.IsOpen) { $serial.Close() }
    $serial.Dispose()
    $timestamped.Dispose()
    $raw.Dispose()
}
