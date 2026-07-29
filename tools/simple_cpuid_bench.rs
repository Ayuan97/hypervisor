//! simple_cpuid_bench.rs - 最简化的 CPUID 时序测试
//! 避免 eac_sim.rs 中的复杂度，直接测量 HV CPUID 开销
//! Build: rustc --edition 2021 -C opt-level=3 -o simple_cpuid_bench.exe simple_cpuid_bench.rs

use std::arch::asm;

const SAMPLES: usize = 10000;

#[inline(never)]
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

#[inline(never)]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem)
        );
    }
    (hi as u64) << 32 | lo as u64
}

fn main() {
    println!("=== Simple CPUID Benchmark ===\n");

    // Warm up
    for _ in 0..100 {
        cpuid_leaf1();
    }

    // Measure
    let mut total = 0u64;
    let mut min = u64::MAX;
    let mut max = 0u64;

    for _ in 0..SAMPLES {
        let t0 = rdtsc();
        cpuid_leaf1();
        let t1 = rdtsc();

        let delta = t1.wrapping_sub(t0);
        total += delta;
        if delta < min { min = delta; }
        if delta > max { max = delta; }
    }

    let avg = total / SAMPLES as u64;

    println!("CPUID leaf 0x1 timing ({} samples):", SAMPLES);
    println!("  Average: {} cycles", avg);
    println!("  Min:     {} cycles", min);
    println!("  Max:     {} cycles", max);
    println!();

    if avg < 500 {
        println!("[+] Excellent: Bare metal or very low HV overhead");
    } else if avg < 3000 {
        println!("[+] Good: Moderate HV overhead (< 3000 cycles)");
    } else if avg < 7500 {
        println!("[!] Warning: High overhead but below EAC VMAware threshold");
    } else {
        println!("[-] FAIL: Above EAC VMAware 7500-cycle threshold!");
        println!("    EAC will detect hypervisor presence.");
    }
}
