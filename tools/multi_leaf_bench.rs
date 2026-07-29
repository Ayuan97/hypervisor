//! multi_leaf_bench.rs - 测试不同 CPUID leaf 的性能
//! Build: rustc --edition 2021 -C opt-level=3 -o multi_leaf_bench.exe multi_leaf_bench.rs

use std::arch::asm;

fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
    }
    (hi as u64) << 32 | lo as u64
}

fn cpuid_leaf(leaf: u32) {
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("eax") leaf => _,
            in("ecx") 0u32,
            lateout("edx") _,
            options(nostack)
        );
    }
}

fn bench_leaf(leaf: u32, name: &str) -> u64 {
    // Warm up
    for _ in 0..50 {
        cpuid_leaf(leaf);
    }

    const SAMPLES: usize = 500;
    let mut deltas = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let t0 = rdtsc();
        cpuid_leaf(leaf);
        let t1 = rdtsc();
        deltas.push(t1.wrapping_sub(t0));
    }

    deltas.sort_unstable();
    let median = deltas[SAMPLES / 2];

    println!("{:<20} median: {:>6} cyc", name, median);
    median
}

fn main() {
    println!("=== Multi-Leaf CPUID Benchmark ===\n");

    bench_leaf(0x0, "Leaf 0x0 (vendor)");
    bench_leaf(0x1, "Leaf 0x1 (features)");
    bench_leaf(0x2, "Leaf 0x2 (cache)");
    bench_leaf(0x7, "Leaf 0x7 (ext feat)");
    bench_leaf(0x80000000, "Leaf 0x80000000");
    bench_leaf(0x80000001, "Leaf 0x80000001");
    bench_leaf(0x40000000, "Leaf 0x40000000");

    println!("\n如果所有 leaf 都很慢 (~16k cycles):");
    println!("  → 可能在虚拟机中运行");
    println!("  → 或 CPU 有严重的性能问题");
    println!("\n如果只有某些 leaf 慢:");
    println!("  → 那些 leaf 触发了微码慢路径");
}
