use {
    crate::error::HypervisorError,
    core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
};

const ZERO_U64: AtomicU64 = AtomicU64::new(0);

pub const MAX_BREADCRUMB_CPUS: usize = 256;
pub const BREADCRUMB_FIELD_COUNT: u64 = 0;
pub const BREADCRUMB_FIELD_EXIT_REASON: u64 = 1;
pub const BREADCRUMB_FIELD_BASIC_REASON: u64 = 2;
pub const BREADCRUMB_FIELD_GUEST_RIP: u64 = 3;
pub const BREADCRUMB_FIELD_GUEST_RSP: u64 = 4;
pub const BREADCRUMB_FIELD_GUEST_CR3: u64 = 5;
pub const BREADCRUMB_FIELD_GUEST_RFLAGS: u64 = 6;
pub const BREADCRUMB_FIELD_EXIT_QUAL: u64 = 7;
pub const BREADCRUMB_FIELD_GUEST_RAX: u64 = 8;
pub const BREADCRUMB_FIELD_GUEST_RCX: u64 = 9;
pub const BREADCRUMB_FIELD_GUEST_RDX: u64 = 10;
pub const BREADCRUMB_FIELD_DETAIL: u64 = 11;
pub const BREADCRUMB_FIELD_LIMIT: usize = 12;

pub static EXIT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static EXIT_CPUID: AtomicU64 = AtomicU64::new(0);
pub static EXIT_EXT_INT: AtomicU64 = AtomicU64::new(0);
pub static EXIT_EXCEPTION: AtomicU64 = AtomicU64::new(0);
pub static EXIT_EPT_VIOLATION: AtomicU64 = AtomicU64::new(0);
pub static EXIT_EPT_MISCONFIG: AtomicU64 = AtomicU64::new(0);
pub static EXIT_CR_ACCESS: AtomicU64 = AtomicU64::new(0);
pub static EXIT_XSETBV: AtomicU64 = AtomicU64::new(0);
pub static EXIT_MSR: AtomicU64 = AtomicU64::new(0);
pub static EXIT_OTHER: AtomicU64 = AtomicU64::new(0);
pub static EXIT_RDTSC: AtomicU64 = AtomicU64::new(0);
pub static EXIT_VMX_INSTR: AtomicU64 = AtomicU64::new(0);
pub static EXIT_PREEMPT: AtomicU64 = AtomicU64::new(0);
pub static LAST_EXIT_REASON: AtomicU64 = AtomicU64::new(u64::MAX);

pub static LAST_MSR_ADDR: AtomicU64 = AtomicU64::new(0);
pub static LAST_MSR_ACTION: AtomicU64 = AtomicU64::new(0);
pub static MSR_READ_COUNT: AtomicU64 = AtomicU64::new(0);
pub static MSR_WRITE_COUNT: AtomicU64 = AtomicU64::new(0);
pub static MSR_GP_INJECTED: AtomicU64 = AtomicU64::new(0);

pub static LAST_HANDLER_ID: AtomicU64 = AtomicU64::new(0);
pub static LAST_HANDLER_DETAIL: AtomicU64 = AtomicU64::new(0);

pub const RING_SIZE: usize = 32;
static RING_IDX: AtomicU64 = AtomicU64::new(0);
static RING_REASON: [AtomicU64; RING_SIZE] = [ZERO_U64; RING_SIZE];
static RING_RIP: [AtomicU64; RING_SIZE] = [ZERO_U64; RING_SIZE];
static RING_QUAL: [AtomicU64; RING_SIZE] = [ZERO_U64; RING_SIZE];
static RING_RAX: [AtomicU64; RING_SIZE] = [ZERO_U64; RING_SIZE];

pub const MAX_TRACKED_CPUS: usize = 64;
static CPU_HEARTBEAT: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static CPU_PHASE: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static CPU_LAST_CPUID_LEAF: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static CPU_TIMER_RIP: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static CPU_TIMER_RIP_COUNT: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];

pub const PHASE_VMEXIT_ENTRY: u64 = 0x10;
pub const PHASE_FAST_CPUID: u64 = 0x40;
pub const PHASE_FAST_CPUID_DONE: u64 = 0x50;
pub const PHASE_FAST_RIP_ADV: u64 = 0x60;
pub const PHASE_CHECK_NMI: u64 = 0x70;
pub const PHASE_PRE_VMRESUME: u64 = 0x80;
pub const PHASE_SLOW_PATH: u64 = 0x20;
pub const PHASE_SLOW_HANDLER: u64 = 0x30;
pub const PHASE_ERROR_HANDLER: u64 = 0xE0;

#[inline]
pub fn cpu_enter_phase(phase: u64) {
    let cpu = rdtscp_aux() as usize & 0x3F;
    CPU_PHASE[cpu].store(phase, Relaxed);
    CPU_HEARTBEAT[cpu].fetch_add(1, Relaxed);
}

#[inline]
pub fn cpu_set_cpuid_leaf(leaf: u64) {
    let cpu = rdtscp_aux() as usize & 0x3F;
    CPU_LAST_CPUID_LEAF[cpu].store(leaf, Relaxed);
}

/// Called from the preemption timer handler to record where the guest was executing.
/// Returns true if NMI should be injected (freeze detected).
#[inline]
pub fn cpu_record_timer_rip(rip: u64) -> bool {
    let cpu = rdtscp_aux() as usize & 0x3F;
    let prev = CPU_TIMER_RIP[cpu].swap(rip, Relaxed);
    if (prev >> 7) == (rip >> 7) {
        let count = CPU_TIMER_RIP_COUNT[cpu].fetch_add(1, Relaxed) + 1;
        // After 200 consecutive fires in same 128B block (~15s):
        // inject NMI to force BSOD + crash dump (normal idle max ~45)
        if count == 200 && !FREEZE_NMI_FIRED.load(Relaxed) {
            if FREEZE_NMI_FIRED.compare_exchange(false, true, Relaxed, Relaxed).is_ok() {
                FREEZE_DETECTED.store(true, Relaxed);
                return true;
            }
        }
    } else {
        CPU_TIMER_RIP_COUNT[cpu].store(0, Relaxed);
    }
    false
}

static FREEZE_NMI_FIRED: AtomicBool = AtomicBool::new(false);

/// Write just this CPU's RIP to CMOS. Uses extended CMOS (ports 0x72/0x73)
/// which BIOS POST typically does NOT clear.
fn cmos_write_rip(cpu: u8, rip: u64) {
    ext_cmos_write(0x00, 0xDE); // magic
    ext_cmos_write(0x01, cpu);
    for b in 0..8u8 {
        ext_cmos_write(0x02 + b, (rip >> (b * 8)) as u8);
    }
    let count = CPU_TIMER_RIP_COUNT[cpu as usize & 0x3F].load(Relaxed);
    ext_cmos_write(0x0A, count as u8);
    ext_cmos_write(0x0B, (count >> 8) as u8);
}

#[inline]
fn ext_cmos_write(offset: u8, value: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x72u16,
            in("al") offset,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x73u16,
            in("al") value,
            options(nomem, nostack),
        );
    }
}

#[inline]
fn ext_cmos_read(offset: u8) -> u8 {
    unsafe {
        let val: u8;
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x72u16,
            in("al") offset,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "in al, dx",
            in("dx") 0x73u16,
            out("al") val,
            options(nomem, nostack),
        );
        val
    }
}

static CMOS_WRITTEN: AtomicBool = AtomicBool::new(false);

/// Write freeze diagnostic data to CMOS RAM (survives hard reboot).
/// Called repeatedly — CMOS always holds the latest snapshot.
/// Layout at CMOS offsets 0x40-0x5F:
///   0x40: magic 0xDE (indicates valid freeze data)
///   0x41: CPU index with highest non-idle stuck count
///   0x42-0x49: RIP of that CPU (8 bytes LE)
///   0x4A-0x4B: stuck count (u16 LE)
///   0x4C: number of CPUs with stuck_count > 50
///   0x4D: second most-stuck CPU index
///   0x4E-0x55: RIP of second CPU (8 bytes LE)
fn freeze_write_cmos_snapshot() {

    // Find CPU with highest stuck count
    let mut best_cpu: u8 = 0xFF;
    let mut best_count: u64 = 0;
    let mut best_rip: u64 = 0;
    let mut second_cpu: u8 = 0xFF;
    let mut second_count: u64 = 0;
    let mut second_rip: u64 = 0;
    let mut stuck_total: u8 = 0;

    for i in 0..MAX_TRACKED_CPUS {
        let count = CPU_TIMER_RIP_COUNT[i].load(Relaxed);
        if count > 50 {
            stuck_total = stuck_total.saturating_add(1);
        }
        if count > best_count {
            second_cpu = best_cpu;
            second_count = best_count;
            second_rip = best_rip;
            best_cpu = i as u8;
            best_count = count;
            best_rip = CPU_TIMER_RIP[i].load(Relaxed);
        } else if count > second_count {
            second_cpu = i as u8;
            second_count = count;
            second_rip = CPU_TIMER_RIP[i].load(Relaxed);
        }
    }

    // Write to CMOS
    cmos_write(0x40, 0xDE); // magic
    cmos_write(0x41, best_cpu);
    for b in 0..8u8 {
        cmos_write(0x42 + b, (best_rip >> (b * 8)) as u8);
    }
    cmos_write(0x4A, best_count as u8);
    cmos_write(0x4B, (best_count >> 8) as u8);
    cmos_write(0x4C, stuck_total);
    cmos_write(0x4D, second_cpu);
    for b in 0..8u8 {
        cmos_write(0x4E + b, (second_rip >> (b * 8)) as u8);
    }
}

#[inline]
fn cmos_write(offset: u8, value: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x70u16,
            in("al") offset,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x71u16,
            in("al") value,
            options(nomem, nostack),
        );
    }
}

#[inline]
fn cmos_read(offset: u8) -> u8 {
    unsafe {
        let val: u8;
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x70u16,
            in("al") offset,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "in al, dx",
            in("dx") 0x71u16,
            out("al") val,
            options(nomem, nostack),
        );
        val
    }
}

/// Read CMOS freeze data via CPUID diag channel (extended CMOS ports 0x72/0x73).
/// field 0: magic(8) | cpu(8) | stuck_count(16) | 0(32)
/// field 1: rip (64-bit)
/// field 4: clear CMOS freeze data, return 0
pub fn cmos_read_freeze(field: u64) -> u64 {
    match field {
        0 => {
            let magic = ext_cmos_read(0x00) as u64;
            let cpu1 = ext_cmos_read(0x01) as u64;
            let stuck_lo = ext_cmos_read(0x0A) as u64;
            let stuck_hi = ext_cmos_read(0x0B) as u64;
            magic | (cpu1 << 8) | (stuck_lo << 16) | (stuck_hi << 24)
        }
        1 => {
            let mut rip: u64 = 0;
            for b in 0..8u8 {
                rip |= (ext_cmos_read(0x02 + b) as u64) << (b * 8);
            }
            rip
        }
        4 => {
            ext_cmos_write(0x00, 0x00);
            0
        }
        _ => u64::MAX,
    }
}

pub fn cpu_diag(cpu: u64, field: u64) -> u64 {
    let c = cpu as usize;
    if c >= MAX_TRACKED_CPUS { return u64::MAX; }
    match field {
        0 => CPU_HEARTBEAT[c].load(Relaxed),
        1 => CPU_PHASE[c].load(Relaxed),
        2 => CPU_LAST_CPUID_LEAF[c].load(Relaxed),
        3 => CPU_TIMER_RIP[c].load(Relaxed),
        4 => CPU_TIMER_RIP_COUNT[c].load(Relaxed),
        _ => u64::MAX,
    }
}

pub fn ring_record(exit_reason: u64, guest_rip: u64, exit_qual: u64, guest_rax: u64) {
    let idx = RING_IDX.fetch_add(1, Relaxed) as usize % RING_SIZE;
    RING_REASON[idx].store(exit_reason, Relaxed);
    RING_RIP[idx].store(guest_rip, Relaxed);
    RING_QUAL[idx].store(exit_qual, Relaxed);
    RING_RAX[idx].store(guest_rax, Relaxed);
}

pub fn ring_entry(slot: u64, field: u64) -> u64 {
    let s = slot as usize;
    if s >= RING_SIZE { return u64::MAX; }
    match field {
        0 => RING_REASON[s].load(Relaxed),
        1 => RING_RIP[s].load(Relaxed),
        2 => RING_QUAL[s].load(Relaxed),
        3 => RING_RAX[s].load(Relaxed),
        _ => u64::MAX,
    }
}

pub fn ring_current_idx() -> u64 {
    RING_IDX.load(Relaxed)
}

pub static CTL_PINBASED: AtomicU64 = AtomicU64::new(0);
pub static CTL_PRIMARY: AtomicU64 = AtomicU64::new(0);
pub static CTL_SECONDARY: AtomicU64 = AtomicU64::new(0);
pub static CTL_EXIT: AtomicU64 = AtomicU64::new(0);
pub static CTL_ENTRY: AtomicU64 = AtomicU64::new(0);
pub static TSC_OFFSET: AtomicU64 = AtomicU64::new(0);
pub static BOOT_STAGE: AtomicU64 = AtomicU64::new(0);
pub static DIAGNOSTICS_SEALED: AtomicBool = AtomicBool::new(false);
pub static CLIENT_READS_ARMED: AtomicBool = AtomicBool::new(false);
const BOOT_STOP_STAGE: u64 = parse_boot_stop_stage(option_env!("HV_BOOT_STOP_STAGE"));

// Freeze detection: global CPUID stall monitor
// Arms only after seeing EAC-level CPUID activity, then triggers when
// CPUIDs stop entirely (guest code frozen).
// Uses CAS on checkpoint counter so exactly one CPU runs the check per round.
static FREEZE_LAST_CPUID: AtomicU64 = AtomicU64::new(0);
static FREEZE_CHECKPOINT: AtomicU64 = AtomicU64::new(0);
static FREEZE_ACTIVE_STREAK: AtomicU64 = AtomicU64::new(0);
static FREEZE_ARMED: AtomicBool = AtomicBool::new(false);
static FREEZE_STALE_ROUNDS: AtomicU64 = AtomicU64::new(0);
pub static FREEZE_DETECTED: AtomicBool = AtomicBool::new(false);
pub static FREEZE_NMI_INJECTED: AtomicU64 = AtomicU64::new(0);

const FREEZE_CHECK_INTERVAL: u64 = 40; // ~2s per check (40 timer fires @ 50ms)
const FREEZE_ACTIVE_MIN: u64 = 5; // any CPUID activity counts as "active"
const FREEZE_ARM_STREAK: u64 = 1; // 1 active round arms the detector
const FREEZE_STALE_THRESHOLD: u64 = 3; // 3 stale rounds (~6s) triggers freeze
const FREEZE_MIN_TOTAL_CPUID: u64 = 20; // very low: arm ASAP after first cpuid_ping

pub fn freeze_check_cpuid_stall() -> bool {
    if FREEZE_DETECTED.load(Relaxed) {
        return true;
    }
    let cur_preempt = EXIT_PREEMPT.load(Relaxed);
    let last_check = FREEZE_CHECKPOINT.load(Relaxed);
    if cur_preempt.wrapping_sub(last_check) < FREEZE_CHECK_INTERVAL {
        return false;
    }
    if FREEZE_CHECKPOINT
        .compare_exchange(last_check, cur_preempt, Relaxed, Relaxed)
        .is_err()
    {
        return false;
    }
    let cur_cpuid = EXIT_CPUID.load(Relaxed);
    if cur_cpuid < FREEZE_MIN_TOTAL_CPUID {
        return false;
    }
    let last_cpuid = FREEZE_LAST_CPUID.swap(cur_cpuid, Relaxed);
    if last_cpuid == 0 {
        return false;
    }
    let delta = cur_cpuid.wrapping_sub(last_cpuid);
    if delta >= FREEZE_ACTIVE_MIN {
        let streak = FREEZE_ACTIVE_STREAK.fetch_add(1, Relaxed) + 1;
        if streak >= FREEZE_ARM_STREAK {
            FREEZE_ARMED.store(true, Relaxed);
        }
        FREEZE_STALE_ROUNDS.store(0, Relaxed);
        return false;
    }
    // Few/no CPUIDs this round
    FREEZE_ACTIVE_STREAK.store(0, Relaxed);
    if !FREEZE_ARMED.load(Relaxed) {
        return false;
    }
    let stale = FREEZE_STALE_ROUNDS.fetch_add(1, Relaxed) + 1;
    if stale >= FREEZE_STALE_THRESHOLD {
        FREEZE_DETECTED.store(true, Relaxed);
        return true;
    }
    false
}

pub fn freeze_diag(field: u64) -> u64 {
    match field {
        0 => FREEZE_DETECTED.load(Relaxed) as u64,
        1 => FREEZE_NMI_INJECTED.load(Relaxed),
        2 => FREEZE_STALE_ROUNDS.load(Relaxed),
        3 => FREEZE_ARMED.load(Relaxed) as u64,
        _ => u64::MAX,
    }
}

static BREADCRUMB_COUNT: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_EXIT_REASON: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_BASIC_REASON: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RIP: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RSP: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_CR3: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RFLAGS: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_EXIT_QUAL: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RAX: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RCX: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RDX: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_DETAIL: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];

pub const fn parse_boot_stop_stage(value: Option<&str>) -> u64 {
    let Some(value) = value else {
        return 0;
    };

    let bytes = value.as_bytes();
    let mut i = 0;
    let mut parsed = 0u64;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte < b'0' || byte > b'9' {
            return 0;
        }
        parsed = parsed * 10 + (byte - b'0') as u64;
        i += 1;
    }
    parsed
}

pub fn set_boot_stage(stage: u64) {
    BOOT_STAGE.store(stage, Relaxed);
    super::diag_trace::trace_stage(stage);
}

pub fn boot_stage(stage: u64) -> Result<(), HypervisorError> {
    set_boot_stage(stage);
    log::info!("hv stage {}", stage);
    if stop_requested_at(stage) {
        log::info!("hv stop stage {}", stage);
        Err(HypervisorError::BootStageStop)
    } else {
        Ok(())
    }
}

pub fn stop_requested_at(stage: u64) -> bool {
    BOOT_STOP_STAGE != 0 && stage >= BOOT_STOP_STAGE
}

pub fn seal_diagnostics() {
    DIAGNOSTICS_SEALED.store(true, Relaxed);
}

pub fn diagnostics_sealed() -> bool {
    DIAGNOSTICS_SEALED.load(Relaxed)
}

pub fn arm_client_reads() {
    crate::intel::client_read::reclaim_completed_result_for_new_client();
    CLIENT_READS_ARMED.store(true, Relaxed);
}

pub fn client_reads_armed() -> bool {
    CLIENT_READS_ARMED.load(Relaxed)
}

pub fn record_current_vmexit(
    exit_reason: u64,
    guest_rip: u64,
    guest_rsp: u64,
    guest_cr3: u64,
    guest_rflags: u64,
    exit_qualification: u64,
    guest_rax: u64,
    guest_rcx: u64,
    guest_rdx: u64,
    detail: u64,
) {
    record_vmexit_for_cpu(
        rdtscp_aux() as usize & 0xFF,
        exit_reason,
        guest_rip,
        guest_rsp,
        guest_cr3,
        guest_rflags,
        exit_qualification,
        guest_rax,
        guest_rcx,
        guest_rdx,
        detail,
    );
}

pub fn record_vmexit_for_cpu(
    cpu: usize,
    exit_reason: u64,
    guest_rip: u64,
    guest_rsp: u64,
    guest_cr3: u64,
    guest_rflags: u64,
    exit_qualification: u64,
    guest_rax: u64,
    guest_rcx: u64,
    guest_rdx: u64,
    detail: u64,
) {
    if cpu >= MAX_BREADCRUMB_CPUS {
        return;
    }

    BREADCRUMB_EXIT_REASON[cpu].store(exit_reason, Relaxed);
    BREADCRUMB_BASIC_REASON[cpu].store(exit_reason & 0xFFFF, Relaxed);
    BREADCRUMB_GUEST_RIP[cpu].store(guest_rip, Relaxed);
    BREADCRUMB_GUEST_RSP[cpu].store(guest_rsp, Relaxed);
    BREADCRUMB_GUEST_CR3[cpu].store(guest_cr3, Relaxed);
    BREADCRUMB_GUEST_RFLAGS[cpu].store(guest_rflags, Relaxed);
    BREADCRUMB_EXIT_QUAL[cpu].store(exit_qualification, Relaxed);
    BREADCRUMB_GUEST_RAX[cpu].store(guest_rax, Relaxed);
    BREADCRUMB_GUEST_RCX[cpu].store(guest_rcx, Relaxed);
    BREADCRUMB_GUEST_RDX[cpu].store(guest_rdx, Relaxed);
    BREADCRUMB_DETAIL[cpu].store(detail, Relaxed);
    BREADCRUMB_COUNT[cpu].fetch_add(1, Relaxed);
}

pub fn breadcrumb(cpu: u64, field: u64) -> u64 {
    let cpu = cpu as usize;
    if cpu >= MAX_BREADCRUMB_CPUS {
        return u64::MAX;
    }

    match field {
        BREADCRUMB_FIELD_COUNT => BREADCRUMB_COUNT[cpu].load(Relaxed),
        BREADCRUMB_FIELD_EXIT_REASON => BREADCRUMB_EXIT_REASON[cpu].load(Relaxed),
        BREADCRUMB_FIELD_BASIC_REASON => BREADCRUMB_BASIC_REASON[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RIP => BREADCRUMB_GUEST_RIP[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RSP => BREADCRUMB_GUEST_RSP[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_CR3 => BREADCRUMB_GUEST_CR3[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RFLAGS => BREADCRUMB_GUEST_RFLAGS[cpu].load(Relaxed),
        BREADCRUMB_FIELD_EXIT_QUAL => BREADCRUMB_EXIT_QUAL[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RAX => BREADCRUMB_GUEST_RAX[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RCX => BREADCRUMB_GUEST_RCX[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RDX => BREADCRUMB_GUEST_RDX[cpu].load(Relaxed),
        BREADCRUMB_FIELD_DETAIL => BREADCRUMB_DETAIL[cpu].load(Relaxed),
        _ => u64::MAX,
    }
}

pub fn rdtscp_aux_pub() -> u32 {
    rdtscp_aux()
}

fn rdtscp_aux() -> u32 {
    let aux: u32;
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("ecx") aux,
            out("eax") _,
            out("edx") _,
            options(nomem, nostack),
        );
    }
    aux
}

pub fn counter(id: u64) -> u64 {
    match id {
        0 => EXIT_TOTAL.load(Relaxed),
        1 => EXIT_CPUID.load(Relaxed),
        2 => EXIT_EXT_INT.load(Relaxed),
        3 => EXIT_EXCEPTION.load(Relaxed),
        4 => EXIT_EPT_VIOLATION.load(Relaxed),
        5 => EXIT_EPT_MISCONFIG.load(Relaxed),
        6 => EXIT_CR_ACCESS.load(Relaxed),
        7 => EXIT_XSETBV.load(Relaxed),
        8 => EXIT_OTHER.load(Relaxed),
        9 => EXIT_MSR.load(Relaxed),
        10 => super::host_idt::HOST_GP_COUNT.load(Relaxed),
        11 => super::host_idt::HOST_NMI_COUNT.load(Relaxed),
        12 => LAST_MSR_ADDR.load(Relaxed),
        13 => LAST_MSR_ACTION.load(Relaxed),
        14 => MSR_READ_COUNT.load(Relaxed),
        15 => MSR_WRITE_COUNT.load(Relaxed),
        16 => MSR_GP_INJECTED.load(Relaxed),
        17 => LAST_HANDLER_ID.load(Relaxed),
        18 => LAST_HANDLER_DETAIL.load(Relaxed),
        19 => super::host_idt::HOST_PF_COUNT.load(Relaxed),
        20 => super::host_idt::HOST_MC_COUNT.load(Relaxed),
        21 => EXIT_RDTSC.load(Relaxed),
        22 => EXIT_VMX_INSTR.load(Relaxed),
        23 => ring_current_idx(),
        24 => EXIT_PREEMPT.load(Relaxed),
        _ => u64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_stop_stage_parser_accepts_decimal_only() {
        assert_eq!(parse_boot_stop_stage(None), 0);
        assert_eq!(parse_boot_stop_stage(Some("")), 0);
        assert_eq!(parse_boot_stop_stage(Some("700")), 700);
        assert_eq!(parse_boot_stop_stage(Some("70x")), 0);
    }

    #[test]
    fn client_read_request_waits_for_worker_completion() {
        let _guard = crate::intel::client_read::test_lock();
        crate::intel::client_read::reset_for_test();

        let seq = crate::intel::client_read::submit_physical_read(0x1000, 8);
        assert_ne!(seq, 0);
        assert_eq!(
            crate::intel::client_read::poll_physical_read(seq),
            crate::intel::client_read::READ_PENDING
        );

        crate::intel::client_read::complete_for_test(seq, 0x1122_3344_5566_7788, true);
        assert_eq!(
            crate::intel::client_read::poll_physical_read(seq),
            0x1122_3344_5566_7788
        );
    }

    #[test]
    fn breadcrumb_records_last_vmexit_for_cpu_slot() {
        reset_breadcrumbs_for_test();

        record_vmexit_for_cpu(
            3,
            0x8000_000a,
            0x1111_2222_3333_4444,
            0x2222_3333_4444_5555,
            0x3333_4444_5555_6666,
            0x202,
            0x7777,
            0xaaaaaaaa_bbbbbbbb,
            0xcccccccc_dddddddd,
            0xeeeeeeee_ffffffff,
            0x1234,
        );

        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_COUNT), 1);
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_EXIT_REASON), 0x8000_000a);
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_BASIC_REASON), 10);
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RIP),
            0x1111_2222_3333_4444
        );
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RSP),
            0x2222_3333_4444_5555
        );
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_CR3),
            0x3333_4444_5555_6666
        );
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_GUEST_RFLAGS), 0x202);
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_EXIT_QUAL), 0x7777);
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RAX),
            0xaaaaaaaa_bbbbbbbb
        );
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RCX),
            0xcccccccc_dddddddd
        );
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RDX),
            0xeeeeeeee_ffffffff
        );
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_DETAIL), 0x1234);
    }

    #[test]
    fn breadcrumb_rejects_out_of_range_queries() {
        reset_breadcrumbs_for_test();

        assert_eq!(breadcrumb(MAX_BREADCRUMB_CPUS as u64, 0), u64::MAX);
        assert_eq!(breadcrumb(0, BREADCRUMB_FIELD_LIMIT as u64), u64::MAX);
    }
}

pub fn control(id: u64) -> u64 {
    match id {
        0 => CTL_PINBASED.load(Relaxed),
        1 => CTL_PRIMARY.load(Relaxed),
        2 => CTL_SECONDARY.load(Relaxed),
        3 => CTL_EXIT.load(Relaxed),
        4 => CTL_ENTRY.load(Relaxed),
        5 => unsafe { crate::utils::nt::IDENTITY_CR3 },
        6 => LAST_EXIT_REASON.load(Relaxed),
        7 => super::host_idt::GP_FAULT_RIP.load(Relaxed),
        8 => TSC_OFFSET.load(Relaxed),
        9 => BOOT_STAGE.load(Relaxed),
        10 => super::host_idt::HOST_IDT_PATCH_CALLS.load(Relaxed),
        11 => super::host_idt::HOST_IDT_PATCH_OK_CALLS.load(Relaxed),
        12 => super::host_idt::current_cpu_index() as u64,
        13 => super::host_idt::current_patch_mask(),
        14 => super::host_idt::current_host_idt_base(),
        15 => super::host_idt::current_host_idt_limit(),
        16 => super::support::vmread_checked(x86::vmx::vmcs::host::IDTR_BASE).unwrap_or(u64::MAX),
        17 => super::host_idt::current_nmi_target(),
        18 => super::host_idt::current_gp_target(),
        19 => super::host_idt::expected_nmi_handler(),
        20 => super::host_idt::expected_gp_handler(),
        21 => super::host_idt::current_mc_target(),
        22 => super::host_idt::expected_mc_handler(),
        23 => super::host_idt::HOST_MC_COUNT.load(Relaxed),
        24 => super::host_idt::MC_FAULT_RIP.load(Relaxed),
        25 => super::host_idt::current_pf_target(),
        26 => super::host_idt::expected_pf_handler(),
        27 => super::host_idt::HOST_PF_COUNT.load(Relaxed),
        28 => super::host_idt::PF_FAULT_RIP.load(Relaxed),
        29 => super::host_idt::PF_FAULT_CR2.load(Relaxed),
        _ => u64::MAX,
    }
}

#[cfg(test)]
pub fn reset_breadcrumbs_for_test() {
    for cpu in 0..MAX_BREADCRUMB_CPUS {
        BREADCRUMB_COUNT[cpu].store(0, Relaxed);
        BREADCRUMB_EXIT_REASON[cpu].store(0, Relaxed);
        BREADCRUMB_BASIC_REASON[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RIP[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RSP[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_CR3[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RFLAGS[cpu].store(0, Relaxed);
        BREADCRUMB_EXIT_QUAL[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RAX[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RCX[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RDX[cpu].store(0, Relaxed);
        BREADCRUMB_DETAIL[cpu].store(0, Relaxed);
    }
}
