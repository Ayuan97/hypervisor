//! cpuid_vmexit_counter.rs - 测量 CPUID 是否真的触发 vmexit
//! 通过 HV comm channel 读取 EXIT_CPUID counter
//! Build: rustc --edition 2021 -C opt-level=3 -o cpuid_vmexit_counter.exe cpuid_vmexit_counter.rs

use std::arch::asm;

const HV_COMM_LEAF: u32 = 0x4000_0000;
const HV_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const CMD_GET_CTL: u64 = 6; // GET_CTL command

fn hv_get_exit_cpuid_count() -> Option<u64> {
    let result: u64;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("rax") HV_COMM_LEAF as u64 => result,
            inlateout("rcx") CMD_GET_CTL => _,
            inlateout("rdx") 1u64 => _, // subcmd 1 = EXIT_CPUID
            in("r8")  0u64,
            in("r9")  0u64,
            in("r10") HV_MAGIC,
            in("r11") HV_MAGIC,
            options(nostack)
        );
    }

    if result == 0 {
        None
    } else {
        Some(result)
    }
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

fn main() {
    println!("=== CPUID vmexit Counter Test ===\n");

    // Check HV alive
    let initial_count = match hv_get_exit_cpuid_count() {
        Some(c) => {
            println!("[+] HV alive, EXIT_CPUID counter = {}", c);
            c
        }
        None => {
            println!("[-] HV not responding");
            return;
        }
    };
    println!();

    // Execute N CPUID instructions
    const N: usize = 1000;
    println!("[*] Executing {} CPUID leaf 0x1 instructions...", N);

    for _ in 0..N {
        cpuid_leaf1();
    }

    println!("[+] Done\n");

    // Check counter again
    let final_count = match hv_get_exit_cpuid_count() {
        Some(c) => c,
        None => {
            println!("[-] HV not responding after test");
            return;
        }
    };

    let delta = final_count - initial_count;

    println!("=== Results ===");
    println!("  CPUID executed:     {} times", N);
    println!("  EXIT_CPUID delta:   {} times", delta);
    println!("  Vmexit ratio:       {:.1}%", (delta as f64 / N as f64) * 100.0);
    println!();

    if delta == 0 {
        println!("[!] CRITICAL: CPUID did NOT trigger any vmexit!");
        println!("    This means CPUID exiting is NOT enabled in VMCS.");
        println!("    The 37k-cycle measurement is WRONG - it's measuring something else!");
    } else if delta < N as u64 {
        println!("[!] WARNING: Only {:.1}% of CPUID triggered vmexit", (delta as f64 / N as f64) * 100.0);
        println!("    Possible causes:");
        println!("    1. Some CPUIDs are cached by CPU");
        println!("    2. CPUID exiting is conditionally enabled");
        println!("    3. Counter is racy (multi-CPU)");
    } else {
        println!("[+] All CPUID instructions triggered vmexit (100%)");
    }
}
