//! comprehensive_cpuid_test.rs - 综合 CPUID 测试
//! 同时检查：hypervisor bit + vmexit counting + timing
//! Build: rustc --edition 2021 -C opt-level=3 -o comprehensive_cpuid_test.exe comprehensive_cpuid_test.rs

use std::arch::asm;

const HV_COMM_LEAF: u32 = 0x4000_0000;
const HV_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;

fn hv_alive() -> bool {
    let result: u64;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("rax") HV_COMM_LEAF as u64 => result,
            inlateout("rcx") 0u64 => _,
            inlateout("rdx") 0u64 => _,
            in("r8")  0u64,
            in("r9")  0u64,
            in("r10") HV_MAGIC,
            in("r11") HV_MAGIC,
            options(nostack)
        );
    }
    result == HV_MAGIC
}

fn hv_get_counter(subcmd: u64) -> Option<u64> {
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
    if result == u64::MAX {
        None
    } else {
        Some(result)
    }
}

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

fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
    }
    (hi as u64) << 32 | lo as u64
}

fn main() {
    println!("=== Comprehensive CPUID Test ===\n");

    // 1. Check HV alive
    if !hv_alive() {
        println!("[-] HV not running");
        return;
    }
    println!("[+] HV is running\n");

    // 2. Check hypervisor bit
    let ecx = cpuid_leaf1();
    let hv_bit = (ecx >> 31) & 1;
    println!("[Test 1: Hypervisor Bit]");
    println!("  CPUID leaf 0x1, ECX = {:#010x}", ecx);
    println!("  Bit 31: {} {}", hv_bit, if hv_bit == 0 { "(hidden ✓)" } else { "(VISIBLE ✗)" });
    println!();

    // 3. Check vmexit counter
    println!("[Test 2: Vmexit Counter]");
    match hv_get_counter(1) {
        Some(initial) => {
            println!("  EXIT_CPUID before: {}", initial);

            // Execute 100 CPUIDs
            for _ in 0..100 {
                cpuid_leaf1();
            }

            match hv_get_counter(1) {
                Some(final_count) => {
                    let delta = final_count.wrapping_sub(initial);
                    println!("  EXIT_CPUID after:  {}", final_count);
                    println!("  Delta: {}", delta);

                    if delta == 0 {
                        println!("  → CPUID is NOT triggering vmexit ✗");
                    } else {
                        println!("  → CPUID is triggering vmexit ({:.0}%) ✓", (delta as f64 / 100.0) * 100.0);
                    }
                }
                None => println!("  → Counter read failed after test"),
            }
        }
        None => println!("  → EXIT_CPUID counter not initialized (u64::MAX)"),
    }
    println!();

    // 4. Timing test
    println!("[Test 3: CPUID Timing]");
    let mut deltas = Vec::with_capacity(100);
    for _ in 0..100 {
        let t0 = rdtsc();
        cpuid_leaf1();
        let t1 = rdtsc();
        deltas.push(t1.wrapping_sub(t0));
    }
    deltas.sort_unstable();
    let median = deltas[50];
    println!("  Median: {} cycles", median);

    if median < 1000 {
        println!("  → Fast (bare metal or efficient HV) ✓");
    } else if median < 7500 {
        println!("  → Moderate (below EAC threshold) ✓");
    } else {
        println!("  → Slow (above EAC threshold) ✗");
    }
    println!();

    // Summary
    println!("=== Summary ===");
    if hv_bit == 0 && median < 7500 {
        println!("[+] PASS: Hypervisor is well-hidden");
        println!("    - Hypervisor bit hidden");
        println!("    - Timing below EAC threshold");
    } else {
        println!("[-] FAIL: Detection risk");
        if hv_bit == 1 {
            println!("    - Hypervisor bit visible!");
        }
        if median >= 7500 {
            println!("    - Timing above EAC threshold!");
        }
    }
}
