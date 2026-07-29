//! check_hypervisor_bit.rs - 检查 CPUID leaf 0x1 ECX bit 31
//! Build: rustc --edition 2021 -C opt-level=3 -o check_hv_bit.exe check_hypervisor_bit.rs

use std::arch::asm;

fn cpuid_leaf1() -> u32 {
    let ecx: u32;
    unsafe {
        asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") ecx,
            out("edx") _,
            options(nostack)
        );
    }
    ecx
}

fn main() {
    println!("=== Hypervisor Presence Bit Check ===\n");

    let ecx = cpuid_leaf1();
    let hv_bit = (ecx >> 31) & 1;

    println!("CPUID leaf 0x1, ECX = {:#010x}", ecx);
    println!("  Bit 31 (Hypervisor Present): {}", hv_bit);
    println!();

    if hv_bit == 1 {
        println!("[!] HYPERVISOR DETECTED!");
        println!("    ECX bit 31 = 1");
        println!("    EAC will detect this immediately.");
        println!();
        println!("Root cause:");
        println!("  CPUID exiting is NOT enabled in VMCS.");
        println!("  Guest executes CPUID directly on hardware.");
        println!("  Hardware returns true hypervisor presence bit.");
    } else {
        println!("[+] Hypervisor bit is hidden (bit 31 = 0)");
        println!("    Either no HV, or HV is properly intercepting CPUID.");
    }
}
