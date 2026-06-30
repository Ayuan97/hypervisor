param(
    [string]$Driver = (Join-Path $PSScriptRoot "..\target\release\matrix.sys")
)

$ErrorActionPreference = "Stop"

$deny = @(
    "hypervisor\\src",
    "driver\\src",
    "matrix.pdb",
    "matrix.dll",
    "matrix.sys",
    "vmexit_handler",
    "vmlaunch_failed",
    "vmresume_failed",
    "Hypervisor",
    "VMEXIT",
    "VMCALL",
    "VMXON",
    "VMCS",
    "CPUID Hypervisor"
)

$bytes = [IO.File]::ReadAllBytes($Driver)
function Get-AsciiStrings([byte[]]$Data) {
    $builder = New-Object Text.StringBuilder

    foreach ($byte in $Data) {
        if ($byte -ge 32 -and $byte -le 126) {
            [void]$builder.Append([char]$byte)
        } else {
            if ($builder.Length -ge 3) {
                [PSCustomObject]@{ Encoding = "ascii"; String = $builder.ToString() }
            }
            [void]$builder.Clear()
        }
    }

    if ($builder.Length -ge 3) {
        [PSCustomObject]@{ Encoding = "ascii"; String = $builder.ToString() }
    }
}

function Get-Utf16LeStrings([byte[]]$Data) {
    foreach ($startOffset in 0..1) {
        $builder = New-Object Text.StringBuilder
        for ($i = $startOffset; $i + 1 -lt $Data.Length; $i += 2) {
            $low = $Data[$i]
            $high = $Data[$i + 1]
            if ($high -eq 0 -and $low -ge 32 -and $low -le 126) {
                [void]$builder.Append([char]$low)
            } else {
                if ($builder.Length -ge 3) {
                    [PSCustomObject]@{ Encoding = "utf16le"; String = $builder.ToString() }
                }
                [void]$builder.Clear()
            }
        }

        if ($builder.Length -ge 3) {
            [PSCustomObject]@{ Encoding = "utf16le"; String = $builder.ToString() }
        }
    }
}

$strings = @(Get-AsciiStrings $bytes) + @(Get-Utf16LeStrings $bytes)

$hits = foreach ($pattern in $deny) {
    $strings | Where-Object {
        $_.String.IndexOf($pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0
    } | ForEach-Object {
        [PSCustomObject]@{ Encoding = $_.Encoding; Pattern = $pattern; String = $_.String }
    }
}

if ($hits) {
    $hits | Format-Table -AutoSize
    throw "release string scan failed"
}

Write-Output "[+] release string scan passed"
