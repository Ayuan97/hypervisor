//! Test: 区分普通 CPUID vs HV comm CPUID
//! Build: rustc --edition 2021 -C opt-level=3 -o test_cpuid_types.exe test_cpuid_types.rs

use std::arch::asm;

const HV_COMM_LEAF: u32 = 0x4000_0000;
const HV_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;

fn hv_get_counter(subcmd: u64) -> u64 {
    let result: u64;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("rax") HV_COMM_LEAF as u64 => result,
            inlateout("rcx") 6u64 => _, // CMD_GET_CTL
            inlateout("rdx") subcmd => _,
            in("r8")  0u64,
            in("r9")  0u64,
            in("r10") HV_MAGIC,
            in("r11") HV_MAGIC,
            options(nostack)
        );
    }
    result
}

fn cpuid_leaf1() {
    unsafe {
        asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack)
        );
    }
}

fn cpuid_leaf0() {
    unsafe {
        asm!(
            "push rbx",
            "mov eax, 0",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack)
        );
    }
}

fn main() {
    println!("=== CPUID Type Differentiation Test ===\n");

    // Get initial counters
    let exit_total_before = hv_get_counter(0);
    let exit_cpuid_before = hv_get_counter(1);

    println!("[*] Initial counters:");
    println!("    EXIT_TOTAL:  {}", exit_total_before);
    println!("    EXIT_CPUID:  {}", exit_cpuid_before);
    println!();

    // Test 1: Normal CPUID leaf 0x1 (100 times)
    println!("[*] Test 1: 100x CPUID leaf 0x1");
    for _ in 0..100 {
        cpuid_leaf1();
    }

    let exit_total_after1 = hv_get_counter(0);
    let exit_cpuid_after1 = hv_get_counter(1);

    println!("    EXIT_TOTAL delta:  {}", exit_total_after1.wrapping_sub(exit_total_before));
    println!("    EXIT_CPUID delta:  {}", exit_cpuid_after1.wrapping_sub(exit_cpuid_before));
    println!();

    // Test 2: Normal CPUID leaf 0x0 (100 times)
    println!("[*] Test 2: 100x CPUID leaf 0x0");
    for _ in 0..100 {
        cpuid_leaf0();
    }

    let exit_total_after2 = hv_get_counter(0);
    let exit_cpuid_after2 = hv_get_counter(1);

    println!("    EXIT_TOTAL delta:  {}", exit_total_after2.wrapping_sub(exit_total_after1));
    println!("    EXIT_CPUID delta:  {}", exit_cpuid_after2.wrapping_sub(exit_cpuid_after1));
    println!();

    println!("=== Analysis ===");
    if exit_cpuid_after2 == u64::MAX {
        println!("[!] EXIT_CPUID counter is uninitialized (u64::MAX)");
        println!("    This confirms CPUID exiting is NOT enabled.");
    } else {
        println!("[+] EXIT_CPUID counter is working");
    }
}
