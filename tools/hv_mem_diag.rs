use std::{
    arch::asm,
    convert::TryInto,
    env,
    ffi::c_void,
    time::{Duration, Instant},
};

const CPUID_LEAF: u64 = 0x4000_0000;
const HV_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;
const STATUS_UNSUPPORTED: u64 = u64::MAX - 2;
const STATUS_PENDING: u64 = u64::MAX - 3;
const CMD_PING: u64 = 0x01;
const CMD_READ_PHYS: u64 = 0x10;
const CMD_GET_GUEST_CR3: u64 = 0x13;
const CMD_ARM_CLIENT_READS: u64 = 0x17;
const CMD_READ_PHYS_RESULT: u64 = 0x18;
const CLIENT_READ_ARM_TOKEN: u64 = 0xC17E_A2D5_90B4_6F31;

const EP_PID: u64 = 0x440;
const EP_LINKS: u64 = 0x448;
const EP_IMAGE_NAME: u64 = 0x5A8;
const EP_DTB: u64 = 0x28;

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

fn hv(cmd: u64, p1: u64, p2: u64, p3: u64) -> u64 {
    let result: u64;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("rax") CPUID_LEAF => result,
            inlateout("rcx") cmd => _,
            inlateout("rdx") p1 => _,
            in("r8") p2,
            in("r9") p3,
            in("r10") HV_MAGIC,
            in("r11") HV_MAGIC,
        );
    }
    result
}

fn failed(v: u64) -> bool {
    matches!(
        v,
        u64::MAX | STATUS_ACCESS_DENIED | STATUS_UNSUPPORTED | STATUS_PENDING
    )
}

fn arm() -> u64 {
    hv(CMD_ARM_CLIENT_READS, CLIENT_READ_ARM_TOKEN, 0, 0)
}

fn read_phys_sized(pa: u64, size: usize) -> Option<u64> {
    let seq = hv(CMD_READ_PHYS, pa, size as u64, 0);
    if seq == 0 || failed(seq) {
        return None;
    }
    let start = Instant::now();
    for i in 0..2_000_000usize {
        if start.elapsed() > Duration::from_secs(15) {
            return None;
        }
        let r = hv(CMD_READ_PHYS_RESULT, seq, 0, 0);
        if r == STATUS_PENDING {
            if i % 512 == 0 {
                std::thread::sleep(Duration::from_micros(500));
            } else if i % 64 == 0 {
                std::thread::yield_now();
            }
            continue;
        }
        if failed(r) {
            return None;
        }
        return Some(r);
    }
    None
}

fn read_phys_bytes(pa: u64, size: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(size);
    let mut left = size;
    let mut cur = pa;
    while left > 0 {
        let chunk = left.min(8);
        let value = read_phys_sized(cur, chunk)?;
        out.extend_from_slice(&value.to_le_bytes()[..chunk]);
        left -= chunk;
        cur += chunk as u64;
    }
    Some(out)
}

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(d: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(off..off + 8)?.try_into().ok()?))
}

fn parse_u64_arg(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn translate(cr3: u64, va: u64) -> Option<u64> {
    let pml4 = cr3 & 0x000F_FFFF_FFFF_F000;
    let i4 = (va >> 39) & 0x1FF;
    let i3 = (va >> 30) & 0x1FF;
    let i2 = (va >> 21) & 0x1FF;
    let i1 = (va >> 12) & 0x1FF;
    let off = va & 0xFFF;

    let e4 = read_phys_sized(pml4 + i4 * 8, 8)?;
    if e4 & 1 == 0 {
        return None;
    }
    let e3 = read_phys_sized((e4 & 0x000F_FFFF_FFFF_F000) + i3 * 8, 8)?;
    if e3 & 1 == 0 {
        return None;
    }
    if e3 & 0x80 != 0 {
        return Some((e3 & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF));
    }
    let e2 = read_phys_sized((e3 & 0x000F_FFFF_FFFF_F000) + i2 * 8, 8)?;
    if e2 & 1 == 0 {
        return None;
    }
    if e2 & 0x80 != 0 {
        return Some((e2 & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }
    let e1 = read_phys_sized((e2 & 0x000F_FFFF_FFFF_F000) + i1 * 8, 8)?;
    if e1 & 1 == 0 {
        return None;
    }
    Some((e1 & 0x000F_FFFF_FFFF_F000) | off)
}

fn kread_raw(cr3: u64, va: u64, size: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(size);
    let mut left = size;
    let mut cur = va;
    while left > 0 {
        let off = (cur & 0xFFF) as usize;
        let chunk = left.min(0x1000 - off);
        let pa = translate(cr3, cur)?;
        out.extend_from_slice(&read_phys_bytes(pa, chunk)?);
        left -= chunk;
        cur += chunk as u64;
    }
    Some(out)
}

fn kread_u64(cr3: u64, va: u64) -> u64 {
    kread_raw(cr3, va, 8)
        .and_then(|d| u64_at(&d, 0))
        .unwrap_or(0)
}

fn kread_u32(cr3: u64, va: u64) -> u32 {
    kread_raw(cr3, va, 4)
        .and_then(|d| u32_at(&d, 0))
        .unwrap_or(0)
}

fn decrypt_client_entities_dword_exact(v: u32) -> u32 {
    let v = v.rotate_left(2);
    let v = v ^ 0x111B9118;
    v.wrapping_add(0x79300E2E)
}

fn decrypt_entity_list_dword(v: u32) -> u32 {
    let v = v.rotate_left(6);
    let v = v ^ 0xC5D748E1;
    v.wrapping_add(0x48498B34)
}

fn decrypt_handle(h: u64, decrypt_fn: fn(u32) -> u32) -> u64 {
    let lo = decrypt_fn(h as u32);
    let hi = decrypt_fn((h >> 32) as u32);
    ((hi as u64) << 32) | (lo as u64)
}

fn il2cpp_get_handle(cr3: u64, ptr: u64) -> u64 {
    if ptr < 0x10000 {
        return 0;
    }
    let page_base = ptr & 0xFFFF_FFFF_FFFF_E000;
    let typ = match kread_raw(cr3, page_base + 0x20, 1) {
        Some(d) if !d.is_empty() => d[0],
        _ => return 0,
    };
    let slot = (ptr - page_base - 0x28) >> 3;
    let entry = kread_u64(cr3, page_base + 8 * (slot + 5));
    if entry == 0 {
        return 0;
    }
    if typ > 1 {
        entry
    } else {
        !entry
    }
}

fn decrypt_wrapper(cr3: u64, wrapper: u64, decrypt_fn: fn(u32) -> u32) -> u64 {
    if wrapper < 0x10000 {
        return 0;
    }
    let raw = kread_u64(cr3, wrapper + 0x18);
    if raw == 0 {
        return 0;
    }
    let dec = decrypt_handle(raw, decrypt_fn);
    if dec & 1 != 0 {
        il2cpp_get_handle(cr3, dec & !1)
    } else {
        kread_u64(cr3, dec)
    }
}

fn print_bn_chain(cr3: u64, ga: u64) {
    println!("\n=== BaseNetworkable Chain Diagnostic ===");
    println!("ga=0x{ga:x}");
    for rva in [0xE1FCD80u64, 0xE334210, 0xE2DAAA8] {
        let klass = kread_u64(cr3, ga + rva);
        let sf = if klass > 0x10000 {
            kread_u64(cr3, klass + 0xB8)
        } else {
            0
        };
        println!("rva=0x{rva:x} klass=0x{klass:x} sf=0x{sf:x}");
        if sf < 0x10000 {
            continue;
        }
        for wrapper_off in (0x0..0x80u64).step_by(8) {
            let wrapper = kread_u64(cr3, sf + wrapper_off);
            if wrapper < 0x10000 {
                continue;
            }
            let ce = decrypt_wrapper(cr3, wrapper, decrypt_client_entities_dword_exact);
            if ce < 0x10000 {
                continue;
            }
            let el_wrapper = kread_u64(cr3, ce + 0x10);
            let el = decrypt_wrapper(cr3, el_wrapper, decrypt_entity_list_dword);
            if el < 0x10000 {
                println!(
                    "  sf+0x{wrapper_off:x} wrapper=0x{wrapper:x} ce=0x{ce:x} elw=0x{el_wrapper:x} el=0"
                );
                continue;
            }
            for buffer_off in [0x10u64, 0x18, 0x20] {
                let bl = kread_u64(cr3, el + buffer_off);
                if bl < 0x10000 {
                    continue;
                }
                let arr = kread_u64(cr3, bl + 0x10);
                let cnt = kread_u32(cr3, bl + 0x18);
                println!(
                    "  sf+0x{wrapper_off:x} wrapper=0x{wrapper:x} ce=0x{ce:x} elw=0x{el_wrapper:x} el=0x{el:x} el+0x{buffer_off:x}=bl 0x{bl:x} arr=0x{arr:x} cnt={cnt}"
                );
            }
        }
    }
}

fn get_ntos_base() -> u64 {
    let mut size = 0u32;
    unsafe {
        let _ = NtQuerySystemInformation(11, std::ptr::null_mut(), 0, &mut size);
    }
    if size == 0 {
        return 0;
    }
    let mut buf = vec![0u8; size as usize + 0x1000];
    let status = unsafe {
        NtQuerySystemInformation(
            11,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut size,
        )
    };
    if status != 0 || buf.len() < 0x20 {
        return 0;
    }
    u64_at(&buf, 0x18).unwrap_or(0)
}

fn find_export(cr3: u64, base: u64, name: &[u8]) -> u64 {
    let dos = match kread_raw(cr3, base, 0x40) {
        Some(v) => v,
        None => return 0,
    };
    let pe_off = match u32_at(&dos, 0x3c) {
        Some(v) => v as u64,
        None => return 0,
    };
    let pe = match kread_raw(cr3, base + pe_off, 0x120) {
        Some(v) => v,
        None => return 0,
    };
    let exp_rva = match u32_at(&pe, 0x88) {
        Some(v) if v != 0 => v as u64,
        _ => return 0,
    };
    let ed = match kread_raw(cr3, base + exp_rva, 0x1000) {
        Some(v) => v,
        None => return 0,
    };
    let num_names = match u32_at(&ed, 0x18) {
        Some(v) => v,
        None => return 0,
    };
    let addr_rva = u32_at(&ed, 0x1c).unwrap_or(0) as u64;
    let name_rva = u32_at(&ed, 0x20).unwrap_or(0) as u64;
    let ord_rva = u32_at(&ed, 0x24).unwrap_or(0) as u64;
    let names = match kread_raw(cr3, base + name_rva, num_names as usize * 4) {
        Some(v) => v,
        None => return 0,
    };
    let ords = match kread_raw(cr3, base + ord_rva, num_names as usize * 2) {
        Some(v) => v,
        None => return 0,
    };
    for i in 0..num_names as usize {
        let n_rva = match u32_at(&names, i * 4) {
            Some(v) => v as u64,
            None => continue,
        };
        let raw = match kread_raw(cr3, base + n_rva, 96) {
            Some(v) => v,
            None => continue,
        };
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        if &raw[..end] == name {
            let ord = u16_at(&ords, i * 2).unwrap_or(0) as u64;
            let func =
                match kread_raw(cr3, base + addr_rva + ord * 4, 4).and_then(|d| u32_at(&d, 0)) {
                    Some(v) => v as u64,
                    None => return 0,
                };
            return base + func;
        }
    }
    0
}

fn image_name(cr3: u64, ep: u64) -> String {
    let raw = kread_raw(cr3, ep + EP_IMAGE_NAME, 15).unwrap_or_default();
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let target_pid = args.get(1).and_then(|s| parse_u64_arg(s)).unwrap_or(0);
    let ga = args.get(2).and_then(|s| parse_u64_arg(s)).unwrap_or(0);
    println!("=== HV Mem Init Diagnostic ===");
    println!("target_pid={}", target_pid);
    println!("arm=0x{:x}", arm());
    println!("ping=0x{:x}", hv(CMD_PING, 0, 0, 0));
    let cr3 = hv(CMD_GET_GUEST_CR3, 0, 0, 0);
    println!("current_cr3=0x{:x}", cr3);
    let ntos = get_ntos_base();
    println!("ntos=0x{:x}", ntos);
    if ntos == 0 || cr3 == 0 {
        return;
    }
    println!(
        "ntos_mz={:?}",
        kread_raw(cr3, ntos, 2).map(|v| format!("{:02x?}", v))
    );
    let ps = find_export(cr3, ntos, b"PsInitialSystemProcess");
    println!("PsInitialSystemProcess=0x{:x}", ps);
    let system_ep = kread_u64(cr3, ps);
    println!(
        "system_ep=0x{:x} image={}",
        system_ep,
        image_name(cr3, system_ep)
    );
    if system_ep == 0 {
        return;
    }

    let mut cur = system_ep;
    let mut found = 0u64;
    for idx in 0..2000u32 {
        let pid = kread_u64(cr3, cur + EP_PID);
        let name = image_name(cr3, cur);
        if idx < 12 || pid == target_pid {
            println!(
                "#{idx:04} ep=0x{cur:x} pid={pid} dtb=0x{:x} image={}",
                kread_u64(cr3, cur + EP_DTB) & !(1u64 << 63),
                name
            );
        }
        if pid == target_pid {
            found = cur;
            break;
        }
        let flink = kread_u64(cr3, cur + EP_LINKS);
        let next = flink.wrapping_sub(EP_LINKS);
        if next == system_ep || next == 0 || next < 0xffff_8000_0000_0000 {
            println!("list_end idx={} flink=0x{:x} next=0x{:x}", idx, flink, next);
            break;
        }
        cur = next;
    }
    println!("target_ep=0x{:x}", found);
    if found != 0 && ga != 0 {
        let target_dtb = kread_u64(cr3, found + EP_DTB) & !(1u64 << 63);
        println!("target_dtb=0x{:x}", target_dtb);
        print_bn_chain(target_dtb, ga);
    }
}
