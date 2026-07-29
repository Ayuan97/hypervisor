//! bare_cpuid_bench.rs - 最简化的裸 CPUID 测量
//! 不用 lfence，只用 rdtsc
//! Build: rustc --edition 2021 -C opt-level=3 -o bare_cpuid_bench.exe bare_cpuid_bench.rs

use std::arch::asm;

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

fn main() {
    println!("=== Bare CPUID Benchmark (no lfence) ===\n");

    // Warm up
    for _ in 0..100 {
        cpuid_leaf1();
    }

    const SAMPLES: usize = 1000;
    let mut deltas = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let t0 = rdtsc();
        cpuid_leaf1();
        let t1 = rdtsc();
        deltas.push(t1.wrapping_sub(t0));
    }

    // Sort to get median and percentiles
    deltas.sort_unstable();

    let min = deltas[0];
    let p5 = deltas[SAMPLES * 5 / 100];
    let p25 = deltas[SAMPLES / 4];
    let median = deltas[SAMPLES / 2];
    let p75 = deltas[SAMPLES * 3 / 4];
    let p95 = deltas[SAMPLES * 95 / 100];
    let max = deltas[SAMPLES - 1];
    let avg: u64 = deltas.iter().sum::<u64>() / SAMPLES as u64;

    println!("CPUID leaf 0x1 timing ({} samples):", SAMPLES);
    println!("  Min:     {:>6} cycles", min);
    println!("  P5:      {:>6} cycles", p5);
    println!("  P25:     {:>6} cycles", p25);
    println!("  Median:  {:>6} cycles", median);
    println!("  Average: {:>6} cycles", avg);
    println!("  P75:     {:>6} cycles", p75);
    println!("  P95:     {:>6} cycles", p95);
    println!("  Max:     {:>6} cycles", max);
    println!();

    if median < 500 {
        println!("[+] Normal: Bare metal CPUID (~100-300 cycles typical)");
        println!("    HV is NOT intercepting CPUID!");
    } else if median < 3000 {
        println!("[!] Moderate overhead detected");
    } else {
        println!("[-] Very high overhead - something is wrong!");
    }
}
