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

# Scrub panic/file! path crumbs that match release string deny list.
# Replace in-place with same-length ASCII spaces so PE layout stays valid.
$pathScrubs = @(
    'hypervisor\src',
    'hypervisor/src',
    'driver\src',
    'driver/src'
)
$pathScrubCount = 0
foreach ($needle in $pathScrubs) {
    $oldPath = [Text.Encoding]::ASCII.GetBytes($needle)
    $space = [byte[]]::new($oldPath.Length)
    for ($k = 0; $k -lt $space.Length; $k++) { $space[$k] = 0x20 }
    for ($i = 0; $i -le $bytes.Length - $oldPath.Length; $i++) {
        $matched = $true
        for ($j = 0; $j -lt $oldPath.Length; $j++) {
            # Case-insensitive ASCII letter match for path roots.
            $a = $bytes[$i + $j]
            $b = $oldPath[$j]
            if ($a -ge 0x41 -and $a -le 0x5A) { $a = $a + 0x20 }
            if ($b -ge 0x41 -and $b -le 0x5A) { $b = $b + 0x20 }
            if ($a -ne $b) { $matched = $false; break }
        }
        if ($matched) {
            [Array]::Copy($space, 0, $bytes, $i, $space.Length)
            $pathScrubCount++
            $i += $oldPath.Length - 1
        }
    }
}

[IO.File]::WriteAllBytes($Destination, $bytes)

# Hard reset / crash can leave a same-size all-zero .sys on disk (torn write).
# Refuse to ship a non-PE so kdmapper does not report "Invalid format of PE image".
$check = [IO.File]::ReadAllBytes($Destination)
if ($check.Length -lt 0x40 -or $check[0] -ne 0x4D -or $check[1] -ne 0x5A) {
    throw "finalize produced non-PE at $Destination (len=$($check.Length))"
}
$peOff = [BitConverter]::ToInt32($check, 0x3C)
if ($peOff -le 0 -or ($peOff + 4) -ge $check.Length) {
    throw "finalize PE e_lfanew invalid at $Destination"
}
$sig = [Text.Encoding]::ASCII.GetString($check, $peOff, 4)
if ($sig -ne 'PE' + [char]0 + [char]0) {
    throw "finalize PE signature invalid at $Destination (got '$sig')"
}

Write-Output "[+] finalized $Destination (patched $count PE name occurrence(s), path_scrubs=$pathScrubCount, pe_ok)"
