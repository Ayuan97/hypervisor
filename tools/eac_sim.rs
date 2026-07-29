//! eac_sim.rs — EAC-like hypervisor detection simulation
//!
//! Probes the same detection vectors EAC is known to use.
//! Run WITHOUT HV for baseline, then WITH HV loaded to audit what leaks.
//!
//! Build: rustc --edition 2021 -o eac_sim.exe eac_sim.rs
//! Run:   eac_sim.exe [--verbose]

#![allow(unsafe_code)]
use std::{
    arch::asm,
    ffi::c_void,
    hint::black_box,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

// ── EAC-known thresholds (VMAware paper; TODO.md R14/R25) ─────────────────
const VMAWARE_CPUID_THRESHOLD_CYCLES: u64 = 7_500; // 2.5 µs @ 3 GHz
const TIMING_SAMPLES: u64 = 512;

// ── Our HV comm channel ────────────────────────────────────────────────────
const HV_COMM_LEAF: u32 = 0x4000_0000;
const HV_MAGIC: u64     = 0xA3B7_E291_4F6D_8C15;
const CMD_PING: u64     = 0x01;

// ── Exception codes ────────────────────────────────────────────────────────
const EX_UD: u32 = 0xC000_001D; // #UD  — illegal instruction
const EX_GP: u32 = 0xC000_0096; // #GP  — privileged / protection fault
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32    =  0;

// ── VEH plumbing (same pattern as probe_test.rs) ──────────────────────────
static LAST_EX: AtomicU32   = AtomicU32::new(0);
static EX_HITS: AtomicUsize = AtomicUsize::new(0);
static SKIP:   AtomicUsize  = AtomicUsize::new(0);

#[repr(C)] struct ExRec  { code: u32, flags: u32, next: *mut ExRec, addr: *mut c_void,
                           nparams: u32, info: [usize; 15] }
#[repr(C)] struct CtxPfx { _home: [u64; 6], _cf: u32, _mx: u32, _segs: [u16; 6],
                           _efl: u32, _dr: [u64; 6],
                           _rax: u64, _rcx: u64, _rdx: u64, _rbx: u64,
                           _rsp: u64, _rbp: u64, _rsi: u64, _rdi: u64,
                           _r8:  u64, _r9:  u64, _r10: u64, _r11: u64,
                           _r12: u64, _r13: u64, _r14: u64, _r15: u64, rip: u64 }
#[repr(C)] struct ExPtrs { ex: *mut ExRec, ctx: *mut CtxPfx }

#[link(name = "kernel32")]
extern "system" {
    fn AddVectoredExceptionHandler(first: u32,
        h: Option<unsafe extern "system" fn(*mut ExPtrs) -> i32>) -> *mut c_void;
    fn RemoveVectoredExceptionHandler(h: *mut c_void) -> u32;
}
unsafe extern "system" fn veh(p: *mut ExPtrs) -> i32 {
    let skip = SKIP.load(Ordering::SeqCst);
    if skip == 0 || p.is_null() { return EXCEPTION_CONTINUE_SEARCH; }
    let ex  = (*p).ex;
    let ctx = (*p).ctx;
    if ex.is_null() || ctx.is_null() { return EXCEPTION_CONTINUE_SEARCH; }
    LAST_EX.store((*ex).code, Ordering::SeqCst);
    EX_HITS.fetch_add(1, Ordering::SeqCst);
    (*ctx).rip = (*ctx).rip.wrapping_add(skip as u64);
    EXCEPTION_CONTINUE_EXECUTION
}

struct VehGuard(*mut c_void);
impl VehGuard {
    fn install() -> Option<Self> {
        let h = unsafe { AddVectoredExceptionHandler(1, Some(veh)) };
        (!h.is_null()).then_some(Self(h))
    }
}
impl Drop for VehGuard {
    fn drop(&mut self) { unsafe { RemoveVectoredExceptionHandler(self.0); } }
}

// ── Probe plumbing ────────────────────────────────────────────────────────
#[derive(Debug, Copy, Clone)]
struct ProbeResult { name: &'static str, ex_code: u32, hit: bool }

fn run_probe(name: &'static str, skip: usize, f: unsafe fn()) -> ProbeResult {
    LAST_EX.store(0, Ordering::SeqCst);
    EX_HITS.store(0, Ordering::SeqCst);
    SKIP.store(skip, Ordering::SeqCst);
    unsafe { f() };
    SKIP.store(0, Ordering::SeqCst);
    ProbeResult { name, ex_code: LAST_EX.load(Ordering::SeqCst),
                  hit: EX_HITS.load(Ordering::SeqCst) != 0 }
}

// ── CPUID helpers ─────────────────────────────────────────────────────────
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        asm!("push rbx", "cpuid", "mov {ebx:e}, ebx", "pop rbx",
             inlateout("eax") leaf => eax, in("ecx") subleaf,
             ebx = lateout(reg) ebx, lateout("ecx") ecx, lateout("edx") edx,
             options(nostack));
    }
    (eax, ebx, ecx, edx)
}

// ── RDTSC helpers ─────────────────────────────────────────────────────────
#[inline(always)]
fn rdtsc_serialized() -> u64 {
    let lo: u32; let hi: u32;
    unsafe { asm!("lfence", "rdtsc", "lfence",
                  out("eax") lo, out("edx") hi, options(nostack, nomem)); }
    (hi as u64) << 32 | lo as u64
}

fn measure_cpuid_cycles(leaf: u32) -> u64 {
    // Warm up
    for _ in 0..16 { black_box(cpuid(black_box(leaf), 0)); }
    let t0 = rdtsc_serialized();
    for _ in 0..TIMING_SAMPLES { black_box(cpuid(black_box(leaf), 0)); }
    let t1 = rdtsc_serialized();
    (t1.saturating_sub(t0)) / TIMING_SAMPLES
}

fn measure_nop_cycles() -> u64 {
    let t0 = rdtsc_serialized();
    for _ in 0..TIMING_SAMPLES {
        unsafe { asm!("nop; nop; nop; nop", options(nostack, nomem)); }
        black_box(());
    }
    let t1 = rdtsc_serialized();
    (t1.saturating_sub(t0)) / TIMING_SAMPLES
}

// ══ CATEGORY 1: CPUID Fingerprinting ═════════════════════════════════════

fn check_hypervisor_present_bit() -> (&'static str, bool, String) {
    let (_eax, _ebx, ecx, _edx) = cpuid(0x1, 0);
    let hv_bit = (ecx >> 31) & 1;
    let pass = hv_bit == 0;
    (if pass { "PASS" } else { "FAIL" }, pass,
     format!("leaf 0x1 ECX bit31 = {} ({})",
             hv_bit, if pass { "not visible" } else { "HV EXPOSED!" }))
}

fn check_hypervisor_vendor_leaf() -> (&'static str, bool, String) {
    let (eax, ebx, ecx, edx) = cpuid(0x4000_0000, 0);
    // EAX = max hypervisor leaf. Normal: 0 or ≤ 0x4. >0x4000_0000 means HV.
    let max_leaf = eax;
    let pass = max_leaf < 0x4000_0001;
    let vendor = {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&ebx.to_le_bytes());
        b[4..8].copy_from_slice(&ecx.to_le_bytes());
        b[8..12].copy_from_slice(&edx.to_le_bytes());
        String::from_utf8_lossy(&b).to_string()
    };
    (if pass { "PASS" } else { "WARN" }, pass,
     format!("0x40000000 EAX=0x{:08x} vendor=\"{}\"", max_leaf,
             vendor.replace('\0', ".")))
}

fn check_extended_hv_leaves_zero() -> (&'static str, bool, String) {
    // EAC checks leaves 0x40000001-0x40000005 should return all zeros on bare metal
    let mut any_nonzero = false;
    let mut detail = String::new();
    for leaf in 0x4000_0001u32..=0x4000_0005 {
        let (a,b,c,d) = cpuid(leaf, 0);
        if a|b|c|d != 0 {
            any_nonzero = true;
            detail = format!("leaf 0x{:08x} = ({:#x},{:#x},{:#x},{:#x})", leaf,a,b,c,d);
            break;
        }
    }
    let pass = !any_nonzero;
    (if pass {"PASS"} else {"WARN"}, pass,
     if pass { "leaves 0x40000001-05 all zero".into() } else { detail })
}

fn check_cpuid_consistency() -> (&'static str, bool, String) {
    // Same leaf should return identical results across 4 calls; variation = HV side-effect
    let r0 = cpuid(0x1, 0);
    let r1 = cpuid(0x1, 0);
    let r2 = cpuid(0x1, 0);
    let pass = r0 == r1 && r1 == r2;
    (if pass {"PASS"} else {"FAIL"}, pass,
     if pass { "leaf 0x1 stable across 3 calls".into() }
     else { format!("INCONSISTENT: {:?} vs {:?}", r0, r2) })
}

// ══ CATEGORY 2: VMX Instruction Probes ═══════════════════════════════════
// All VMX instructions must raise #UD from ring 3 (CPL=3).
// If our HV injects #UD correctly, EAC cannot distinguish from bare metal.

unsafe fn probe_vmread()   { asm!("xor eax,eax","vmread rax,rax", out("rax") _, options(nostack)); }
unsafe fn probe_vmwrite()  { asm!("xor eax,eax","vmwrite rax,rax",out("rax") _, options(nostack)); }
unsafe fn probe_vmlaunch() { asm!(".byte 0x0f,0x01,0xc2", options(nostack)); }
unsafe fn probe_vmresume() { asm!(".byte 0x0f,0x01,0xc3", options(nostack)); }
unsafe fn probe_vmxoff()   { asm!(".byte 0x0f,0x01,0xc4", options(nostack)); }
unsafe fn probe_vmcall()   { asm!("vmcall", options(nostack)); }
unsafe fn probe_encls()    { asm!(".byte 0x0f,0x01,0xcf", options(nostack)); }
unsafe fn probe_enclv()    { asm!(".byte 0x0f,0x01,0xc0", options(nostack)); }

fn check_vmx_instructions(veh_installed: bool) -> Vec<(&'static str, bool, String)> {
    let specs: &[(&str, usize, unsafe fn())] = &[
        ("VMREAD",   3, probe_vmread),
        ("VMWRITE",  3, probe_vmwrite),
        ("VMLAUNCH", 3, probe_vmlaunch),
        ("VMRESUME", 3, probe_vmresume),
        ("VMXOFF",   3, probe_vmxoff),
        ("VMCALL",   3, probe_vmcall),
        ("ENCLS",    3, probe_encls),
        ("ENCLV",    3, probe_enclv),
    ];
    if !veh_installed { return vec![("VMX", false, "VEH not installed".into())]; }
    specs.iter().map(|&(name, skip, f)| {
        let r = run_probe(name, skip, f);
        let pass = r.hit && r.ex_code == EX_UD;
        (if pass {"PASS"} else {"FAIL"}, pass,
         format!("{:<8} hit={} code=0x{:08x} {}",
                 name, r.hit, r.ex_code,
                 if pass {"(#UD ✓)"} else {"← WRONG EXCEPTION"}))
    }).collect()
}

// ══ CATEGORY 3: RDTSC Timing ══════════════════════════════════════════════
// EAC (VMAware paper) flags CPUID overhead > 2.5 µs (≈7500 cyc @3GHz).
// Our HV handler ≈ 2600 cycles → ~0.86 µs → well below threshold.

fn check_cpuid_timing() -> Vec<(&'static str, bool, String)> {
    let nop_cyc    = measure_nop_cycles();
    let cyc_leaf1  = measure_cpuid_cycles(0x1);
    let cyc_leaf80 = measure_cpuid_cycles(0x8000_0000);
    let cyc_leafhv = measure_cpuid_cycles(0x4000_0000);

    let overhead1  = cyc_leaf1.saturating_sub(nop_cyc);
    let overhead80 = cyc_leaf80.saturating_sub(nop_cyc);
    let overheadhv = cyc_leafhv.saturating_sub(nop_cyc);

    let pass1  = overhead1  < VMAWARE_CPUID_THRESHOLD_CYCLES;
    let pass80 = overhead80 < VMAWARE_CPUID_THRESHOLD_CYCLES;
    let passhv = overheadhv < VMAWARE_CPUID_THRESHOLD_CYCLES;

    vec![
        ("PASS", true,
         format!("baseline NOP loop:  {:>6} cyc/iter", nop_cyc)),
        (if pass1  {"PASS"} else {"FAIL"}, pass1,
         format!("CPUID leaf 0x1:      {:>6} cyc  overhead {:>6}  threshold {}",
                 cyc_leaf1, overhead1, VMAWARE_CPUID_THRESHOLD_CYCLES)),
        (if pass80 {"PASS"} else {"FAIL"}, pass80,
         format!("CPUID leaf 0x80000000:{:>5} cyc  overhead {:>6}",
                 cyc_leaf80, overhead80)),
        (if passhv {"PASS"} else {"WARN"}, passhv,
         format!("CPUID leaf 0x40000000:{:>5} cyc  overhead {:>6}  (our HV comm leaf)",
                 cyc_leafhv, overheadhv)),
    ]
}

// ══ CATEGORY 4: MSR / Privileged Instructions ═════════════════════════════
unsafe fn probe_rdmsr_vmx_basic() {
    asm!("rdmsr", in("ecx") 0x480u32,
         lateout("eax") _, lateout("edx") _, options(nostack));
}
unsafe fn probe_wrmsr_reserved() {
    asm!("wrmsr", in("ecx") 0x4000_0000u32,
         in("eax") 0u32, in("edx") 0u32, options(nostack));
}
unsafe fn probe_hlt() { asm!("hlt", options(nostack)); }

fn check_msr_behavior(veh_installed: bool) -> Vec<(&'static str, bool, String)> {
    if !veh_installed { return vec![("MSR", false, "VEH not installed".into())]; }
    let rdmsr = run_probe("RDMSR(0x480)", 2, probe_rdmsr_vmx_basic);
    let wrmsr = run_probe("WRMSR(0x4000_0000)", 2, probe_wrmsr_reserved);
    let hlt   = run_probe("HLT", 1, probe_hlt);
    let rd_ok = rdmsr.hit && rdmsr.ex_code == EX_GP;
    let wr_ok = wrmsr.hit && wrmsr.ex_code == EX_GP;
    let hl_ok = hlt.hit   && hlt.ex_code   == EX_GP;
    vec![
        (if rd_ok {"PASS"} else {"FAIL"}, rd_ok,
         format!("RDMSR IA32_VMX_BASIC → 0x{:08x} ({})", rdmsr.ex_code,
                 if rd_ok {"#GP ✓"} else {"unexpected"})),
        (if wr_ok {"PASS"} else {"FAIL"}, wr_ok,
         format!("WRMSR reserved MSR  → 0x{:08x} ({})", wrmsr.ex_code,
                 if wr_ok {"#GP ✓"} else {"unexpected"})),
        (if hl_ok {"PASS"} else {"WARN"}, hl_ok,
         format!("HLT from ring-3      → 0x{:08x} ({})", hlt.ex_code,
                 if hl_ok {"#GP ✓"} else {"may vary"})),
    ]
}

// ══ CATEGORY 5: GDT/IDT Artifacts ═════════════════════════════════════════
// SIDT/SGDT work from ring-3. EAC checks limit and base address for anomalies.
// Normal kernel IDT limit = 0x0FFF (256 entries × 16 bytes).
// Normal kernel GDT limit ≈ 0x007F (small GDT).

#[repr(C, packed)] struct DtReg { limit: u16, base: u64 }

fn get_idtr() -> DtReg {
    let mut r = DtReg { limit: 0, base: 0 };
    unsafe { asm!("sidt [{}]", in(reg) &mut r, options(nostack)); }
    r
}

fn get_gdtr() -> DtReg {
    let mut r = DtReg { limit: 0, base: 0 };
    unsafe { asm!("sgdt [{}]", in(reg) &mut r, options(nostack)); }
    r
}

fn check_idt_artifacts() -> Vec<(&'static str, bool, String)> {
    let idt = get_idtr();
    let gdt = get_gdtr();
    // Copy fields to avoid unaligned reference errors with packed struct
    let idt_limit = idt.limit;
    let idt_base = idt.base;
    let gdt_limit = gdt.limit;
    let gdt_base = gdt.base;

    let idt_ok = idt_limit >= 0x0800 && idt_limit <= 0x1000 && (idt_base >> 48) == 0xFFFF;
    let gdt_ok = gdt_limit >= 0x0040 && gdt_limit <= 0x0200 && (gdt_base >> 48) == 0xFFFF;
    vec![
        (if idt_ok {"PASS"} else {"WARN"}, idt_ok,
         format!("SIDT limit 0x{:04x} base 0x{:016x} ({})",
                 idt_limit, idt_base,
                 if idt_ok {"normal kernel IDT"} else {"unexpected"})),
        (if gdt_ok {"PASS"} else {"WARN"}, gdt_ok,
         format!("SGDT limit 0x{:04x} base 0x{:016x} ({})",
                 gdt_limit, gdt_base,
                 if gdt_ok {"normal kernel GDT"} else {"unexpected"})),
    ]
}

// ══ CATEGORY 6: HV Self-Ping ══════════════════════════════════════════════
// Our HV comm channel (CPUID 0x40000000 with magic in r10/r11).
// This verifies HV is active; not an "EAC sees this" test.

fn check_hv_selfping() -> (&'static str, bool, String) {
    let result: u64;
    unsafe {
        asm!("push rbx", "cpuid", "pop rbx",
             inlateout("rax") HV_COMM_LEAF as u64 => result,
             inlateout("rcx") CMD_PING => _,
             inlateout("rdx") 0u64 => _,
             in("r8")  0u64, in("r9")  0u64,
             in("r10") HV_MAGIC, in("r11") HV_MAGIC,
             options(nostack));
    }
    let active = result == HV_MAGIC || result == (u64::MAX - 1);
    (if active {"INFO"} else {"INFO"}, active,
     if active { format!("HV active (response 0x{:016x})", result) }
     else      { "HV not loaded".into() })
}

// ══ Main ══════════════════════════════════════════════════════════════════

fn main() {
    println!("═══ EAC-like Hypervisor Detection Simulation ═══\n");
    let _verbose = std::env::args().any(|a| a == "--verbose" || a == "-v");

    let _veh = VehGuard::install();
    let veh_ok = _veh.is_some();
    if !veh_ok { println!("[-] VEH install failed; MSR/VMX probes skipped\n"); }

    let mut passed = 0usize;
    let mut total  = 0usize;

    macro_rules! run_checks {
        ($title:expr, $checks:expr) => {
            println!("[{}]", $title);
            for (status, ok, detail) in $checks {
                if ok { passed += 1; }
                total += 1;
                println!("  {} {}", status, detail);
            }
            println!();
        };
    }

    // Category 1: CPUID Fingerprinting
    {
        let (s1, ok1, d1) = check_hypervisor_present_bit();
        let (s2, ok2, d2) = check_hypervisor_vendor_leaf();
        let (s3, ok3, d3) = check_extended_hv_leaves_zero();
        let (s4, ok4, d4) = check_cpuid_consistency();
        run_checks!("CPUID Fingerprinting", vec![(s1,ok1,d1),(s2,ok2,d2),(s3,ok3,d3),(s4,ok4,d4)]);
    }

    // Category 2: VMX Instruction Probes
    run_checks!("VMX Instruction Probes (#UD validation)", check_vmx_instructions(veh_ok));

    // Category 3: RDTSC Timing
    run_checks!("RDTSC Timing (VMAware threshold check)", check_cpuid_timing());

    // Category 4: MSR / Privileged Instructions
    run_checks!("MSR / Privileged Instruction Behavior", check_msr_behavior(veh_ok));

    // Category 5: GDT/IDT Artifacts
    run_checks!("GDT/IDT Artifacts (SIDT/SGDT)", check_idt_artifacts());

    // Category 6: HV Self-Ping
    {
        let (s, _ok, d) = check_hv_selfping();
        println!("[HV Self-Ping (our comm channel)]");
        println!("  {} {}\n", s, d);
        // Don't count in pass/fail since it's informational
    }

    // Summary
    println!("═══════════════════════════════════════════════════");
    println!("Summary: {}/{} checks passed", passed, total);
    if passed == total {
        println!("[+] All EAC-detectable vectors PASS — HV looks clean");
        std::process::exit(0);
    } else {
        println!("[-] {} check(s) FAILED — anomalies detected by EAC-like probes", total - passed);
        std::process::exit(1);
    }
}
