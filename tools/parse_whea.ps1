# CPER (Common Platform Error Record) parser for WHEA-Logger events.
# Extracts human-readable info from the RawData blob attached to each event.
#
# Usage:
#   powershell -NoProfile -File parse_whea.ps1                  # last 10 events
#   powershell -NoProfile -File parse_whea.ps1 -Count 20        # last 20
#   powershell -NoProfile -File parse_whea.ps1 -RecentOnly      # today's only
param(
    [int]$Count = 10,
    [switch]$RecentOnly
)

# --- GUID lookup tables (UEFI CPER spec + Intel additions) ---
$SectionTypeGuids = @{
    '9876CCAD-47B4-4BDB-B65E-16F193C4F3DB' = 'Processor Generic'
    'DC3EA0B0-A144-4797-B95B-53FA242B6E1D' = 'Processor IA32/x64'
    'A5BC1114-6F64-4EDE-B863-3E83ED7C83B1' = 'Memory Error'
    'D995E954-BBC1-430F-AD91-B44DCB3C6F35' = 'PCIe Error'
    'C5753963-3B84-4095-BF78-EDDAD3F9C9DD' = 'PCI/PCI-X Bus Error'
    'EB5E4685-CA66-4769-B6A2-26068B001326' = 'PCI/PCI-X Device Error'
    'E71254E7-C1B9-4940-AB76-909703A4320F' = 'DMAr Generic Error'
    '81212A96-09ED-4996-9471-8D729C8E69ED' = 'Firmware Error Record Reference'
    '85183A8B-9C41-429C-939C-5C3C087CA280' = 'Memory Error V2'
    '036F84E1-7F37-428C-A79E-575FDFAA84EC' = 'IOMMU (Intel VT-d) Error'
    '66A4613D-40AB-9A40-A698-F362D464B38F' = 'Boot Error (variant)'
}

$NotificationTypeGuids = @{
    '2DCE8BB1-BDD7-450E-B9AD-9CF4EBD4F890' = 'CMC (Corrected Machine Check)'
    '4E292F96-D843-4A55-A8C2-D481F27EBEEE' = 'CPE (Corrected Platform Error)'
    'E8F56FFE-919C-4CC5-BA88-65ABE14913BB' = 'MCE (Machine Check Exception)'
    'CF93C01F-1A16-4DFC-B8BC-9C4DAF67C104' = 'PCIe Error'
    'CC5263E8-9308-454A-89D0-340BD39BC98E' = 'INIT'
    '5BAD89FF-B7E6-42C9-814A-CF2485D6E98A' = 'NMI'
    '3D61A466-AB40-409A-A698-F362D464B38F' = 'Boot Error'
    '667DD791-C6B3-4C27-8A6B-0F8E722DEB41' = 'DMAr'
    '9A78788A-BBE8-11E4-809E-67611E5D46B0' = 'SEA (Synchronous External Abort)'
    'BD C4 07 CF 89 B7 18 4E B3 C4 1F 73 2C B5 71 31' = 'raw MCE bytes'
}

$IA32ProcErrorTypeGuids = @{
    'A55701F5-E3EF-43DE-AC72-249B573FAD2C' = 'Cache Check'
    'FC06B535-5E1F-4562-9F25-0A3B9ADB63C3' = 'TLB Check'
    '1CF3F8B3-C5B1-49A2-AA59-5EEF92FFA63C' = 'Bus/Interconnect Check'
    '48AB7F57-DC34-4F6C-A7D3-B0B5B0A74314' = 'Microarchitecture Check'
}

$Severities = @{ 0 = 'RECOVERABLE'; 1 = 'FATAL'; 2 = 'CORRECTED'; 3 = 'INFO' }

function Get-GuidFromBytes([byte[]]$bytes, [int]$offset) {
    $d1 = [BitConverter]::ToUInt32($bytes, $offset)
    $d2 = [BitConverter]::ToUInt16($bytes, $offset + 4)
    $d3 = [BitConverter]::ToUInt16($bytes, $offset + 6)
    $d4 = ($bytes[($offset+8)..($offset+15)] | ForEach-Object { $_.ToString('X2') }) -join ''
    return ('{0:X8}-{1:X4}-{2:X4}-{3}-{4}' -f $d1, $d2, $d3, $d4.Substring(0, 4), $d4.Substring(4))
}

function Decode-McaCheckInfo([UInt64]$check) {
    # Cache/TLB/Bus check_info decoding (IA32/x64 spec)
    $ttMap  = @{ 0='Instr'; 1='Data'; 2='Generic'; 3='Unknown' }
    $llMap  = @{ 0='L0'; 1='L1'; 2='L2'; 3='L3'; 4='LG' }
    $opMap  = @{ 0='Gen'; 1='Read'; 2='DataW'; 3='InstFetch'; 4='Prefetch'; 5='Eviction'; 6='Snoop' }
    $tt = ($check -shr 0)  -band 0x3
    $ll = ($check -shr 2)  -band 0x3
    $op = ($check -shr 4)  -band 0xF
    $tr = ($check -shr 8)  -band 0x1
    $tv = ($check -shr 9)  -band 0x1
    $pcc = ($check -shr 60) -band 0x1
    $uc = ($check -shr 61) -band 0x1
    $en = ($check -shr 62) -band 0x1
    $ov = ($check -shr 63) -band 0x1
    $flags = @()
    if ($ov)  { $flags += 'OVER' }
    if ($en)  { $flags += 'EN' }
    if ($uc)  { $flags += 'UC' }
    if ($pcc) { $flags += 'PCC' }
    return "$($ttMap[[int]$tt])/$($llMap[[int]$ll])/op=$($opMap[[int]$op]) tr=$tr tv=$tv [$($flags -join ',')]"
}

function Parse-Cper([byte[]]$data) {
    if ($data.Length -lt 128) { Write-Host "  (raw too short: $($data.Length) bytes)"; return }
    $sig = [System.Text.Encoding]::ASCII.GetString($data[0..3])
    if ($sig -ne 'CPER') { Write-Host "  (bad signature: $sig)"; return }
    $revision = [BitConverter]::ToUInt16($data, 4)
    $sectionCount = [BitConverter]::ToUInt16($data, 10)
    $severity = [BitConverter]::ToUInt32($data, 12)
    $recordLen = [BitConverter]::ToUInt32($data, 20)
    $notifGuid = Get-GuidFromBytes $data 80
    $recordId  = [BitConverter]::ToUInt64($data, 96)

    $sevName = $Severities[[int]$severity]
    $notifName = if ($NotificationTypeGuids.ContainsKey($notifGuid)) { $NotificationTypeGuids[$notifGuid] } else { $notifGuid }
    Write-Host ("  Severity: $sevName | Sections: $sectionCount | Notify: $notifName | Rec# 0x$($recordId.ToString('X'))")

    for ($i = 0; $i -lt $sectionCount; $i++) {
        $off = 128 + $i * 72
        $secOff = [BitConverter]::ToUInt32($data, $off)
        $secLen = [BitConverter]::ToUInt32($data, $off + 4)
        $secSev = [BitConverter]::ToUInt32($data, $off + 48)
        $typeGuid = Get-GuidFromBytes $data ($off + 16)
        $typeName = if ($SectionTypeGuids.ContainsKey($typeGuid)) { $SectionTypeGuids[$typeGuid] } else { "Unknown ($typeGuid)" }
        Write-Host ("    [$i] $typeName @$secOff len=$secLen sev=$($Severities[[int]$secSev])")

        if ($typeName -eq 'Processor IA32/x64' -and $secOff + $secLen -le $data.Length) {
            Parse-IA32Section $data $secOff $secLen
        } elseif ($typeName -eq 'Memory Error' -and $secOff + $secLen -le $data.Length) {
            Parse-MemorySection $data $secOff $secLen
        } elseif ($typeName -eq 'PCIe Error' -and $secOff + $secLen -le $data.Length) {
            Parse-PCIeSection $data $secOff $secLen
        } elseif ($typeName -eq 'Firmware Error Record Reference' -and $secOff + $secLen -le $data.Length) {
            Parse-FirmwareRefSection $data $secOff $secLen
        }
    }
}

function Parse-FirmwareRefSection([byte[]]$data, [int]$offset, [int]$length) {
    if ($length -lt 32) { return }
    $fwType = $data[$offset]
    $typeName = @{ 0='IPF SAL'; 1='SOC Type1'; 2='SOC Type2' }[[int]$fwType]
    if (-not $typeName) { $typeName = "unknown($fwType)" }
    $recId = [BitConverter]::ToUInt64($data, $offset + 8)
    $recGuid = Get-GuidFromBytes $data ($offset + 16)
    Write-Host ("      FW type=$typeName rec_id=0x$($recId.ToString('X')) rec_guid=$recGuid")
    # Dump first 256 bytes of implementation-specific payload as hex+ASCII grid
    $payloadOff = $offset + 32
    $payloadLen = [Math]::Min(256, $length - 32)
    Write-Host "      Payload hex (first $payloadLen bytes):"
    for ($row = 0; $row -lt $payloadLen; $row += 16) {
        $lineHex = ""
        $lineAscii = ""
        for ($c = 0; $c -lt 16 -and ($row + $c) -lt $payloadLen; $c++) {
            $b = $data[$payloadOff + $row + $c]
            $lineHex += "{0:X2} " -f $b
            $lineAscii += if ($b -ge 32 -and $b -lt 127) { [char]$b } else { '.' }
        }
        Write-Host ("        {0:X4}: {1,-48} {2}" -f $row, $lineHex, $lineAscii)
    }
    # Try scanning for known MC MSR patterns (bit 63 VAL set → MCi_STATUS candidate)
    Write-Host "      Scanning payload for MCi_STATUS candidates (bit63 set):"
    $foundStatus = 0
    for ($p = $payloadOff; $p + 8 -le $offset + $length; $p += 8) {
        $v = [BitConverter]::ToUInt64($data, $p)
        if (($v -shr 63) -band 1) {
            $rel = $p - $payloadOff
            $mcaCode = $v -band 0xFFFF
            $modelCode = ($v -shr 16) -band 0xFFFF
            $uc = ($v -shr 61) -band 1
            $pcc = ($v -shr 57) -band 1
            $addrV = ($v -shr 58) -band 1
            $miscV = ($v -shr 59) -band 1
            $en = ($v -shr 60) -band 1
            $ov = ($v -shr 62) -band 1
            Write-Host ("        [+0x{0:X}]  MCi_STATUS=0x{1:X16}  MCA=0x{2:X4} Model=0x{3:X4} UC={4} PCC={5} EN={6} OVER={7} AddrV={8} MiscV={9}" -f $rel, $v, [uint16]$mcaCode, [uint16]$modelCode, $uc, $pcc, $en, $ov, $addrV, $miscV)
            $foundStatus++
            if ($foundStatus -ge 8) { break }
        }
    }
    if ($foundStatus -eq 0) { Write-Host "        (none)" }
}

function Parse-IA32Section([byte[]]$data, [int]$offset, [int]$length) {
    if ($length -lt 64) { return }
    $valid = [BitConverter]::ToUInt64($data, $offset)
    $lapic = [BitConverter]::ToUInt64($data, $offset + 8)
    Write-Host ("      LAPIC ID: 0x$($lapic.ToString('X'))  validity=0x$($valid.ToString('X'))")
    $cursor = $offset + 64  # skip fixed header
    # First skip past cpuid_info (48 bytes) if valid bit 1 set
    if ($valid -band 0x2) { $cursor += 48 }
    $procErrCount = ($valid -shr 2) -band 0x3F
    $ctxInfoCount = ($valid -shr 8) -band 0x3F
    Write-Host ("      Proc-err blocks: $procErrCount  Ctx-info blocks: $ctxInfoCount")

    for ($i = 0; $i -lt $procErrCount; $i++) {
        if ($cursor + 64 -gt $offset + $length) { break }
        $errGuid = Get-GuidFromBytes $data $cursor
        $errType = if ($IA32ProcErrorTypeGuids.ContainsKey($errGuid)) { $IA32ProcErrorTypeGuids[$errGuid] } else { "Unknown ($errGuid)" }
        $peValid = [BitConverter]::ToUInt64($data, $cursor + 16)
        $check   = [BitConverter]::ToUInt64($data, $cursor + 24)
        $tgtAddr = [BitConverter]::ToUInt64($data, $cursor + 88)
        $reqId   = [BitConverter]::ToUInt64($data, $cursor + 96)
        $rspId   = [BitConverter]::ToUInt64($data, $cursor + 104)
        $instIp  = [BitConverter]::ToUInt64($data, $cursor + 112)
        Write-Host ("      Err[$i]: $errType")
        Write-Host ("        check_info=0x$($check.ToString('X16')) → $(Decode-McaCheckInfo $check)")
        if ($peValid -band 0x4) { Write-Host ("        target_addr=0x$($tgtAddr.ToString('X'))") }
        if ($peValid -band 0x20) { Write-Host ("        instruction_ip=0x$($instIp.ToString('X'))") }
        $cursor += 120
    }

    for ($i = 0; $i -lt $ctxInfoCount; $i++) {
        if ($cursor + 16 -gt $offset + $length) { break }
        $ctxType = [BitConverter]::ToUInt16($data, $cursor)
        $regSize = [BitConverter]::ToUInt16($data, $cursor + 2)
        $bankMsr = [BitConverter]::ToUInt32($data, $cursor + 4)
        $mmMsrAddr = [BitConverter]::ToUInt64($data, $cursor + 8)
        $ctxTypeName = @{
            0='Unclassified'; 1='MSR'; 2='Ctx32'; 3='Ctx64'; 4='FXSAVE'; 5='DebugRegs';
            6='MemMapped'; 7='PCIComp'; 8='PCIeCap'; 9='OEM'
        }[[int]$ctxType]
        $bankInfo = if ($ctxType -eq 1) { " (MSR base=0x$($bankMsr.ToString('X')))" } else { "" }
        Write-Host ("      Ctx[$i]: type=$ctxTypeName reg_size=$regSize$bankInfo")
        # Print register values (each u64)
        $regStart = $cursor + 16
        $numRegs = [Math]::Min(16, [int]($regSize / 8))
        for ($j = 0; $j -lt $numRegs; $j++) {
            $regOff = $regStart + $j * 8
            if ($regOff + 8 -le $offset + $length) {
                $val = [BitConverter]::ToUInt64($data, $regOff)
                if ($val -ne 0) {
                    Write-Host ("        reg[$j]=0x$($val.ToString('X16'))")
                }
            }
        }
        $cursor += 16 + $regSize
    }
}

function Parse-MemorySection([byte[]]$data, [int]$offset, [int]$length) {
    if ($length -lt 80) { return }
    $valid  = [BitConverter]::ToUInt64($data, $offset)
    $physAddr = [BitConverter]::ToUInt64($data, $offset + 16)
    $physMask = [BitConverter]::ToUInt64($data, $offset + 24)
    $node   = [BitConverter]::ToUInt16($data, $offset + 32)
    $card   = [BitConverter]::ToUInt16($data, $offset + 34)
    $module = [BitConverter]::ToUInt16($data, $offset + 36)
    $bank   = [BitConverter]::ToUInt16($data, $offset + 38)
    $device = [BitConverter]::ToUInt16($data, $offset + 40)
    $row    = [BitConverter]::ToUInt16($data, $offset + 42)
    $col    = [BitConverter]::ToUInt16($data, $offset + 44)
    Write-Host ("      Physical: 0x$($physAddr.ToString('X'))  mask=0x$($physMask.ToString('X'))")
    Write-Host ("      Node=$node card=$card module=$module bank=$bank device=$device row=$row col=$col")
}

function Parse-PCIeSection([byte[]]$data, [int]$offset, [int]$length) {
    if ($length -lt 48) { return }
    $portType = [BitConverter]::ToUInt32($data, $offset + 8)
    $busSeg = [BitConverter]::ToUInt16($data, $offset + 32)
    $bus = [BitConverter]::ToUInt16($data, $offset + 34)
    $dev = [BitConverter]::ToUInt16($data, $offset + 36)
    Write-Host ("      Port type=$portType bus=${busSeg}:${bus} dev=$dev")
}

# --- Main ---
$filter = @{ LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger' }
if ($RecentOnly) {
    $filter['StartTime'] = (Get-Date).Date
}
$events = Get-WinEvent -FilterHashtable $filter -MaxEvents $Count -ErrorAction SilentlyContinue
if (-not $events) { Write-Host "No WHEA events"; exit 0 }

Write-Host "=== Parsing $($events.Count) WHEA events ==="
foreach ($evt in $events) {
    Write-Host ""
    Write-Host "==================================================================="
    Write-Host ("$($evt.TimeCreated)  EventID=$($evt.Id)")
    $xml = [xml]$evt.ToXml()
    $rawHex = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'RawData' })."#text"
    if (-not $rawHex) { Write-Host "  (no RawData)"; continue }
    $bytes = for ($i = 0; $i -lt $rawHex.Length; $i += 2) {
        [Convert]::ToByte($rawHex.Substring($i, 2), 16)
    }
    Parse-Cper ([byte[]]$bytes)
}
