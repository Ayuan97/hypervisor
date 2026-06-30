param(
    [string]$Source = (Join-Path $PSScriptRoot "..\target\release\matrix.dll"),
    [string]$Destination = (Join-Path $PSScriptRoot "..\target\release\matrix.sys")
)

$ErrorActionPreference = "Stop"

Copy-Item -LiteralPath $Source -Destination $Destination -Force

$old = [Text.Encoding]::ASCII.GetBytes("matrix.dll")
$replacementName = "disk.sys"
$new = [byte[]]::new($old.Length)
[Text.Encoding]::ASCII.GetBytes($replacementName, 0, $replacementName.Length, $new, 0) > $null
$bytes = [IO.File]::ReadAllBytes($Destination)
$count = 0

for ($i = 0; $i -le $bytes.Length - $old.Length; $i++) {
    $matched = $true
    for ($j = 0; $j -lt $old.Length; $j++) {
        if ($bytes[$i + $j] -ne $old[$j]) {
            $matched = $false
            break
        }
    }

    if ($matched) {
        [Array]::Copy($new, 0, $bytes, $i, $new.Length)
        $count++
        $i += $old.Length - 1
    }
}

if ($count -eq 0) {
    throw "matrix.dll export name was not found in $Destination"
}

[IO.File]::WriteAllBytes($Destination, $bytes)
Write-Output "[+] finalized $Destination (patched $count PE name occurrence(s))"
