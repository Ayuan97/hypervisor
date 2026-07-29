use std::arch::asm;

fn cpuid_leaf(leaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            inlateout("eax") leaf => eax,
            in("ecx") 0u32,
            ebx = lateout(reg) ebx,
            lateout("ecx") ecx,
            lateout("edx") edx,
            options(nostack)
        );
    }
    (eax, ebx, ecx, edx)
}

fn main() {
    println!("=== CPUID Leaf 0x40000000 Test ===\n");

    let (eax, ebx, ecx, edx) = cpuid_leaf(0x40000000);

    println!("CPUID leaf 0x40000000:");
    println!("  EAX = {:#010x}", eax);
    println!("  EBX = {:#010x} ('{}')", ebx, u32_to_str(ebx));
    println!("  ECX = {:#010x} ('{}')", ecx, u32_to_str(ecx));
    println!("  EDX = {:#010x} ('{}')", edx, u32_to_str(edx));
    println!();

    let vendor = format!("{}{}{}", u32_to_str(ebx), u32_to_str(ecx), u32_to_str(edx));
    println!("Hypervisor vendor: '{}'", vendor);
    println!();

    if eax == 0 && ebx == 0 && ecx == 0 && edx == 0 {
        println!("[+] Leaf 0x40000000 returns all zeros (hidden)");
    } else if vendor.trim().is_empty() {
        println!("[!] Leaf 0x40000000 returns non-zero but no vendor string");
    } else {
        println!("[!] HYPERVISOR VENDOR VISIBLE!");
        println!("    EAC will detect this.");
    }
}

fn u32_to_str(val: u32) -> String {
    let bytes = val.to_le_bytes();
    bytes.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}
