//! Offline decoder for hv_cmos_capture.txt.
//!
//! This tool only parses the one-shot text capture. It never opens CMOS ports,
//! talks to the hypervisor, or clears any record.

use std::{convert::TryInto, env, fs, process};

const CMOS_BYTES: usize = 128;
const SLOT_SIZE: usize = 32;

fn main() {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| r"D:\cheat\hv_cmos_capture.txt".to_owned());
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => fail(format!("read {}: {}", path, error)),
    };
    let raw = match parse_capture(&text) {
        Ok(raw) => raw,
        Err(error) => fail(error),
    };

    println!("capture_path={}", path);
    println!("capture_bytes={} source=extended_cmos ports=0x72/0x73", raw.len());
    println!("raw_sha_note=raw_hex_preserved_no_cmos_write");
    decode_terminal(&raw);
    decode_legacy(&raw);
    print_raw(&raw);
}

fn fail(message: String) -> ! {
    eprintln!("decode error: {}", message);
    process::exit(1);
}

fn parse_capture(text: &str) -> Result<[u8; CMOS_BYTES], String> {
    let line = text
        .lines()
        .find_map(|line| line.strip_prefix("raw_hex="))
        .ok_or_else(|| "missing raw_hex= line".to_owned())?;
    if line.len() != CMOS_BYTES * 2 {
        return Err(format!("raw_hex has {} characters, expected {}", line.len(), CMOS_BYTES * 2));
    }
    let mut raw = [0u8; CMOS_BYTES];
    for (index, pair) in line.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex(pair[0]).ok_or_else(|| format!("invalid hex at byte {}", index))?;
        let lo = hex(pair[1]).ok_or_else(|| format!("invalid hex at byte {}", index))?;
        raw[index] = (hi << 4) | lo;
    }
    Ok(raw)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_terminal(raw: &[u8; CMOS_BYTES]) {
    let mut found = false;
    for (name, base) in [("A", 0usize), ("B", SLOT_SIZE)] {
        let slot = &raw[base..base + SLOT_SIZE];
        if slot[0] != 0xD8 || slot[31] != 0xA7 || crc8(&slot[..30]) != slot[30] {
            continue;
        }
        found = true;
        let kind = kind_name(slot[1]);
        let seq = u16::from_le_bytes([slot[2], slot[3]]);
        let cpu = slot[4];
        let phase = slot[5];
        let reason = slot[6];
        let flags = slot[7];
        let vmerr = slot[8];
        let session = slot[9];
        let rip = le_u64(&slot[10..18]);
        let qual = le_u64(&slot[18..26]);
        let detail = slot[26];
        let active = le_u24(&slot[27..30]);
        println!(
            "terminal_slot={} valid=1 kind={} kind_id={} seq={} session={} cpu={} phase=0x{:02x} reason=0x{:02x} flags=0x{:02x} vm_error={} rip=0x{:016x} qualification=0x{:016x} detail=0x{:02x} active_bitmap=0x{:06x}",
            name,
            kind,
            slot[1],
            seq,
            session,
            cpu,
            phase,
            reason,
            flags,
            if vmerr == 0xff { "invalid".to_owned() } else { format!("0x{:02x}", vmerr) },
            rip,
            qual,
            detail,
            active
        );
    }
    if found {
        println!("terminal_format=recognized");
    }

    let emergency = &raw[0x70..0x80];
    if emergency[0] == 0xE8 && emergency[15] == 0x5A && crc8(&emergency[..14]) == emergency[14] {
        println!(
            "terminal_emergency=valid kind={} kind_id={} cpu={} vector={} rip=0x{:016x} error=0x{:04x}",
            kind_name(emergency[1]),
            emergency[1],
            emergency[2],
            emergency[3],
            le_u64(&emergency[4..12]),
            u16::from_le_bytes([emergency[12], emergency[13]])
        );
    } else {
        println!("terminal_emergency=invalid_or_empty");
    }

    if found {
        let mut any_cpu = false;
        for cpu in 0..24usize {
            let state = raw[0x40 + cpu];
            let phase = raw[0x58 + cpu];
            if state != 0 || phase != 0 {
                any_cpu = true;
                println!(
                    "terminal_cpu cpu={} active={} reason=0x{:02x} checkpoint_epoch={} phase_code={}",
                    cpu,
                    (state & 0x80) != 0,
                    state & 0x7f,
                    phase >> 4,
                    phase & 0x0f
                );
            }
        }
        if any_cpu {
            println!("terminal_cpu_state=present");
        }
    }
}

fn decode_legacy(raw: &[u8; CMOS_BYTES]) {
    let rare_magic = raw[0];
    if rare_magic == 0xD6 || rare_magic == 0xD7 {
        println!(
            "legacy_rare_ring magic=0x{:02x} head={} count={} format={} slot0={} slot1={}",
            rare_magic,
            raw[1],
            raw[2],
            raw[3],
            format_legacy_rare(&raw[4..10], raw[0x1a], raw[0x1c]),
            format_legacy_rare(&raw[10..16], raw[0x1b], raw[0x1d])
        );
    } else {
        println!("legacy_rare_ring=invalid_or_empty magic=0x{:02x}", rare_magic);
    }

    if raw[0x10] == 0xAB {
        println!(
            "legacy_step4 magic=0xab bugcheck_hits={} first_vector=0x{:02x} first_cpu={} total={} arg0=0x{:08x}",
            raw[0x11],
            raw[0x12],
            raw[0x19],
            u16::from_le_bytes([raw[0x13], raw[0x14]]),
            u32::from_le_bytes([raw[0x15], raw[0x16], raw[0x17], raw[0x18]])
        );
    } else {
        println!("legacy_step4=invalid_or_empty magic=0x{:02x}", raw[0x10]);
    }
    println!(
        "legacy_flags bugcheck_callback=0x{:02x} bugcheck_entry_hook=0x{:02x}",
        raw[0x1f], raw[0x1e]
    );

    for (name, base) in [("A", 0x30usize), ("B", 0x40usize)] {
        if base + 15 >= CMOS_BYTES {
            continue;
        }
        let magic = raw[base];
        if magic != 0x4c && magic != 0x4d {
            continue;
        }
        let seq = u16::from_le_bytes([raw[base + 1], raw[base + 2]]);
        let bitmap = le_u64(&raw[base + 4..base + 12]);
        let last_exit = raw[base + 12];
        if magic == 0x4c {
            let expected = xor_checksum(&raw[base..base + 14]);
            println!(
                "legacy_layer3 slot={} magic=0x4c seq={} valid={} port80=0x{:02x} active_bitmap=0x{:016x} last_exit=0x{:02x} active_count={} checksum=0x{:02x}",
                name,
                seq,
                raw[base + 14] == expected,
                raw[base + 3],
                bitmap,
                last_exit,
                raw[base + 13],
                raw[base + 14]
            );
        } else {
            let expected = xor_checksum(&raw[base..base + 15]);
            println!(
                "legacy_layer3 slot={} magic=0x4d seq={} valid={} port80=0x{:02x} active_bitmap=0x{:016x} last_exit=0x{:02x} phase=0x{:02x} command=0x{:02x} checksum=0x{:02x}",
                name,
                seq,
                raw[base + 15] == expected,
                raw[base + 3],
                bitmap,
                last_exit,
                raw[base + 13],
                raw[base + 14],
                raw[base + 15]
            );
        }
    }

    if raw[0x2d] == 0xA5 {
        let seq = u16::from_le_bytes([raw[0x2e], raw[0x2f]]);
        println!("legacy_layer6_header magic=0xa5 seq={}", seq);
    } else {
        println!("legacy_layer6_header magic=0x{:02x} seq=0x{:02x}{:02x} (may collide with freeze/boot-stage)", raw[0x2d], raw[0x2f], raw[0x2e]);
    }
    if raw[0x58] == 0xB7 {
        println!("legacy_boot_stage magic=0xb7 stage={} cpu={}", u16::from_le_bytes([raw[0x59], raw[0x5a]]), raw[0x5b]);
    }
    if raw[0x20] == 0xC3 {
        let checksum = raw[0x2c];
        let mut expected = 0u8;
        for byte in &raw[0x20..0x2c] {
            expected ^= *byte;
        }
        println!("legacy_retention magic=0xc3 counter={} last_session=0x{:08x} this_session=0x{:08x} completion=0x{:02x} checksum_valid={}", u16::from_le_bytes([raw[0x21], raw[0x22]]), le_u32(&raw[0x23..0x27]), le_u32(&raw[0x27..0x2b]), raw[0x2b], checksum == expected);
    }
}

fn format_legacy_rare(slot: &[u8], vector: u8, meta: u8) -> String {
    format!(
        "cpu={} reason=0x{:02x} rip_low32=0x{:08x} vector=0x{:02x} meta=0x{:02x}",
        slot[0],
        slot[1],
        u32::from_le_bytes([slot[2], slot[3], slot[4], slot[5]]),
        vector,
        meta
    )
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        1 => "periodic",
        2 => "stalled_handler",
        3 => "rare_exit",
        4 => "vm_entry_failure",
        5 => "vmresume_failure",
        6 => "handler_error",
        7 => "host_fault",
        8 => "bugcheck",
        9 => "session_start",
        _ => "unknown",
    }
}

fn le_u24(bytes: &[u8]) -> u32 {
    (bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16)
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("u32 slice"))
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("u64 slice"))
}

fn crc8(bytes: &[u8]) -> u8 {
    let mut crc = 0u8;
    for byte in bytes {
        crc ^= *byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x07 } else { crc << 1 };
        }
    }
    crc
}

fn xor_checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum ^ byte)
}

fn print_raw(raw: &[u8; CMOS_BYTES]) {
    println!("raw_dump_begin");
    for (line, chunk) in raw.chunks(16).enumerate() {
        print!("raw[0x{:02x}..0x{:02x}]=", line * 16, line * 16 + chunk.len() - 1);
        for byte in chunk {
            print!("{:02x}", byte);
        }
        println!();
    }
    println!("raw_dump_end");
}
