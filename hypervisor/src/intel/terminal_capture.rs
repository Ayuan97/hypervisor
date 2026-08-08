//! Reboot-persistent terminal flight recorder for whole-machine freezes.
//!
//! This build profile owns extended CMOS 0x00..=0x7f. Normal VM-exit work is
//! published only to RAM. CMOS is touched for one-second checkpoints, unusual
//! exits, explicit fatal paths, or when another CPU observes a handler that
//! has stopped making progress.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering};

const RELAXED: Ordering = Ordering::Relaxed;
const ACQUIRE: Ordering = Ordering::Acquire;
const RELEASE: Ordering = Ordering::Release;

pub const MAX_CPUS: usize = 24;
pub const CMOS_BYTES: usize = 128;

const SLOT_SIZE: usize = 32;
const SLOT_A_BASE: u8 = 0x00;
const SLOT_B_BASE: u8 = 0x20;
const CPU_REASON_BASE: u8 = 0x40;
const CPU_PHASE_BASE: u8 = 0x58;
const EMERGENCY_BASE: u8 = 0x70;

const SLOT_MAGIC: u8 = 0xD8;
const SLOT_COMMIT: u8 = 0xA7;
const EMERGENCY_MAGIC: u8 = 0xE8;
const EMERGENCY_COMMIT: u8 = 0x5A;
const FORMAT_VERSION: u8 = 1;

const FLAG_ACTIVE: u8 = 1 << 0;
const FLAG_ENTRY_FAILURE: u8 = 1 << 1;
const FLAG_RIP_VALID: u8 = 1 << 2;
const FLAG_QUAL_VALID: u8 = 1 << 3;
const FLAG_VMERR_VALID: u8 = 1 << 4;

pub const KIND_PERIODIC: u8 = 1;
pub const KIND_STALLED_HANDLER: u8 = 2;
pub const KIND_RARE_EXIT: u8 = 3;
pub const KIND_VM_ENTRY_FAILURE: u8 = 4;
pub const KIND_VMRESUME_FAILURE: u8 = 5;
pub const KIND_HANDLER_ERROR: u8 = 6;
pub const KIND_HOST_FAULT: u8 = 7;
pub const KIND_BUGCHECK: u8 = 8;
pub const KIND_SESSION_START: u8 = 9;

pub const INVALID_VM_ERROR: u8 = 0xff;
const HANDLER_STALL_CYCLES: u64 = 50_000_000;
const STALL_SCAN_INTERVAL_CYCLES: u64 = HANDLER_STALL_CYCLES / 4;

const ZERO_U8: AtomicU8 = AtomicU8::new(0);
const ZERO_U64: AtomicU64 = AtomicU64::new(0);

static CMOS_IO_LOCK: AtomicBool = AtomicBool::new(false);
static CMOS_IO_CONTENTION: AtomicU64 = AtomicU64::new(0);

static PREVIOUS_CMOS: [AtomicU8; CMOS_BYTES] = [ZERO_U8; CMOS_BYTES];
static PREVIOUS_CAPTURED: AtomicBool = AtomicBool::new(false);

static CPU_ACTIVE: [AtomicU8; MAX_CPUS] = [ZERO_U8; MAX_CPUS];
static CPU_CONTEXT_SEQUENCE: [AtomicU64; MAX_CPUS] = [ZERO_U64; MAX_CPUS];
static CPU_CONTEXT_FLAGS: [AtomicU8; MAX_CPUS] = [ZERO_U8; MAX_CPUS];
static CPU_REASON: [AtomicU8; MAX_CPUS] = [ZERO_U8; MAX_CPUS];
static CPU_PHASE: [AtomicU8; MAX_CPUS] = [ZERO_U8; MAX_CPUS];
static CPU_RIP: [AtomicU64; MAX_CPUS] = [ZERO_U64; MAX_CPUS];
static CPU_QUALIFICATION: [AtomicU64; MAX_CPUS] = [ZERO_U64; MAX_CPUS];
static CPU_PROGRESS_TSC: [AtomicU64; MAX_CPUS] = [ZERO_U64; MAX_CPUS];
static CPU_STALL_REPORTED: [AtomicU8; MAX_CPUS] = [ZERO_U8; MAX_CPUS];

static LAST_CPU: AtomicU8 = AtomicU8::new(0);
static RECORD_SEQUENCE: AtomicU16 = AtomicU16::new(0);
static SESSION_ID: AtomicU8 = AtomicU8::new(0);
static CHECKPOINT_EPOCH: AtomicU8 = AtomicU8::new(0);
static LAST_STALL_SCAN_TSC: AtomicU64 = AtomicU64::new(0);
// Once a terminal event has committed, periodic checkpoints must not publish
// a newer generic record over it. The emergency capsule remains the fallback
// when the fatal writer itself loses the CMOS lock.
static TERMINAL_FATAL_LATCH: AtomicU8 = AtomicU8::new(0);

static LAST_HOST_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_BUGCHECK_COUNT: AtomicU64 = AtomicU64::new(0);

pub const fn enabled_by_flags(terminal: Option<&str>, cmos_only: Option<&str>) -> bool {
    flag_is_one(terminal) || flag_is_one(cmos_only)
}

const fn flag_is_one(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 1 && bytes[0] == b'1'
}

#[inline(always)]
pub const fn enabled() -> bool {
    enabled_by_flags(
        option_env!("HV_TERMINAL_CAPTURE"),
        option_env!("HV_CMOS_CAPTURE_ONLY"),
    )
}

#[inline(always)]
pub const fn terminal_mode() -> bool {
    flag_is_one(option_env!("HV_TERMINAL_CAPTURE"))
}

#[inline(always)]
pub const fn cmos_capture_only() -> bool {
    flag_is_one(option_env!("HV_CMOS_CAPTURE_ONLY"))
}

struct CmosGuard;

impl Drop for CmosGuard {
    fn drop(&mut self) {
        CMOS_IO_LOCK.store(false, RELEASE);
    }
}

#[inline(always)]
fn try_cmos_lock() -> Option<CmosGuard> {
    if CMOS_IO_LOCK
        .compare_exchange(false, true, ACQUIRE, RELAXED)
        .is_ok()
    {
        Some(CmosGuard)
    } else {
        CMOS_IO_CONTENTION.fetch_add(1, RELAXED);
        None
    }
}

#[inline(always)]
unsafe fn read_cmos_unlocked(offset: u8) -> u8 {
    let value: u8;
    core::arch::asm!(
        "out dx, al",
        in("dx") 0x72u16,
        in("al") offset,
        options(nomem, nostack),
    );
    core::arch::asm!(
        "in al, dx",
        in("dx") 0x73u16,
        out("al") value,
        options(nomem, nostack),
    );
    value
}

#[inline(always)]
unsafe fn write_cmos_unlocked(offset: u8, value: u8) {
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

/// Snapshot the previous boot before any diagnostic writer can change CMOS.
pub fn capture_previous_cmos() -> bool {
    if !enabled() {
        return false;
    }
    if PREVIOUS_CAPTURED
        .compare_exchange(false, true, ACQUIRE, RELAXED)
        .is_err()
    {
        return true;
    }
    let Some(_guard) = try_cmos_lock() else {
        PREVIOUS_CAPTURED.store(false, RELEASE);
        return false;
    };
    for offset in 0..CMOS_BYTES {
        let value = unsafe { read_cmos_unlocked(offset as u8) };
        PREVIOUS_CMOS[offset].store(value, RELAXED);
    }
    true
}

pub fn previous_captured() -> bool {
    PREVIOUS_CAPTURED.load(ACQUIRE)
}

pub fn previous_byte(offset: usize) -> u8 {
    PREVIOUS_CMOS
        .get(offset)
        .map(|value| value.load(RELAXED))
        .unwrap_or(0)
}

pub fn copy_previous_cmos(output: &mut [u8; CMOS_BYTES]) -> bool {
    if !previous_captured() {
        return false;
    }
    for (index, value) in output.iter_mut().enumerate() {
        *value = PREVIOUS_CMOS[index].load(RELAXED);
    }
    true
}

/// Start a new recorder session after the previous bytes are safely in RAM.
pub fn initialize_session() -> bool {
    if !enabled() {
        return false;
    }

    let mut previous = [0u8; CMOS_BYTES];
    let previous_record = if copy_previous_cmos(&mut previous) {
        newest_record(&previous)
    } else {
        None
    };
    let session = previous_record
        .map(|record| record.session.wrapping_add(1).max(1))
        .unwrap_or(1);
    SESSION_ID.store(session, RELAXED);
    RECORD_SEQUENCE.store(0, RELAXED);
    CHECKPOINT_EPOCH.store(0, RELAXED);
    TERMINAL_FATAL_LATCH.store(0, RELAXED);

    let Some(_guard) = try_cmos_lock() else {
        return false;
    };
    for offset in 0..CMOS_BYTES {
        unsafe { write_cmos_unlocked(offset as u8, 0) };
    }
    drop(_guard);

    force_current(KIND_SESSION_START, INVALID_VM_ERROR, FORMAT_VERSION)
}

#[inline(always)]
pub fn handler_begin(tsc: u64) {
    if !enabled() {
        return;
    }
    let cpu = super::host_idt::current_cpu_index();
    if cpu >= MAX_CPUS {
        return;
    }

    CPU_PHASE[cpu].store(super::diag::PHASE_VMEXIT_ENTRY as u8, RELAXED);
    CPU_PROGRESS_TSC[cpu].store(tsc, RELEASE);
    CPU_STALL_REPORTED[cpu].store(0, RELAXED);
    CPU_ACTIVE[cpu].store(1, RELEASE);
    LAST_CPU.store(cpu as u8, RELAXED);
}

#[inline(always)]
pub fn handler_entry(
    exit_reason: u64,
    rip: Option<u64>,
    qualification: Option<u64>,
    tsc: u64,
) {
    if !enabled() {
        return;
    }
    let cpu = super::host_idt::current_cpu_index();
    if cpu >= MAX_CPUS {
        return;
    }

    let sequence = CPU_CONTEXT_SEQUENCE[cpu].fetch_add(1, ACQUIRE);
    CPU_REASON[cpu].store((exit_reason & 0xff) as u8, RELAXED);
    CPU_RIP[cpu].store(rip.unwrap_or(0), RELAXED);
    CPU_QUALIFICATION[cpu].store(qualification.unwrap_or(0), RELAXED);
    let flags = (if rip.is_some() { FLAG_RIP_VALID } else { 0 })
        | (if qualification.is_some() {
            FLAG_QUAL_VALID
        } else {
            0
        });
    CPU_CONTEXT_FLAGS[cpu].store(flags, RELAXED);
    CPU_CONTEXT_SEQUENCE[cpu].store(sequence.wrapping_add(2), RELEASE);
    CPU_PHASE[cpu].store(super::diag::PHASE_VMEXIT_CAPTURED as u8, RELAXED);
    CPU_PROGRESS_TSC[cpu].store(tsc, RELEASE);
    CPU_STALL_REPORTED[cpu].store(0, RELAXED);
    CPU_ACTIVE[cpu].store(1, RELEASE);
    LAST_CPU.store(cpu as u8, RELAXED);

    maybe_scan_stalled_handlers(tsc, Some(cpu));

    if is_rare_exit(exit_reason) {
        let kind = if exit_reason & (1u64 << 31) != 0 {
            KIND_VM_ENTRY_FAILURE
        } else {
            KIND_RARE_EXIT
        };
        let _ = force_cpu(kind, cpu, INVALID_VM_ERROR, 0);
    }
}

#[inline(always)]
pub fn handler_phase(phase: u64) {
    if !enabled() {
        return;
    }
    let cpu = super::host_idt::current_cpu_index();
    if cpu >= MAX_CPUS {
        return;
    }
    CPU_PHASE[cpu].store(phase as u8, RELAXED);
    CPU_PROGRESS_TSC[cpu].store(unsafe { x86::time::rdtsc() }, RELEASE);
}

#[inline(always)]
pub fn handler_exit() {
    if !enabled() {
        return;
    }
    let cpu = super::host_idt::current_cpu_index();
    if cpu >= MAX_CPUS {
        return;
    }
    CPU_PROGRESS_TSC[cpu].store(unsafe { x86::time::rdtsc() }, RELEASE);
    CPU_ACTIVE[cpu].store(0, RELEASE);
}

pub fn poll_stalled_handlers() {
    if enabled() {
        scan_stalled_handlers(unsafe { x86::time::rdtsc() }, None);
        capture_async_fatal_state();
    }
}

pub fn periodic_checkpoint() -> bool {
    if !enabled() {
        return false;
    }
    poll_stalled_handlers();

    let epoch = CHECKPOINT_EPOCH
        .fetch_add(1, RELAXED)
        .wrapping_add(1)
        & 0x0f;
    let Some(_guard) = try_cmos_lock() else {
        return false;
    };
    for cpu in 0..MAX_CPUS {
        let active = CPU_ACTIVE[cpu].load(ACQUIRE) != 0;
        let reason = CPU_REASON[cpu].load(RELAXED) & 0x7f;
        let state = reason | if active { 0x80 } else { 0 };
        let phase = phase_code(CPU_PHASE[cpu].load(RELAXED));
        unsafe {
            write_cmos_unlocked(CPU_REASON_BASE + cpu as u8, state);
            write_cmos_unlocked(CPU_PHASE_BASE + cpu as u8, (epoch << 4) | phase);
        }
    }
    drop(_guard);

    if TERMINAL_FATAL_LATCH.load(ACQUIRE) != 0 {
        return true;
    }
    let cpu = (LAST_CPU.load(RELAXED) as usize).min(MAX_CPUS - 1);
    force_cpu(KIND_PERIODIC, cpu, INVALID_VM_ERROR, epoch)
}

pub fn force_current(kind: u8, vm_error: u8, detail: u8) -> bool {
    if !enabled() {
        return false;
    }
    let current = super::host_idt::current_cpu_index();
    // The terminal CMOS summary has 24 slots while RDTSCP AUX can expose a
    // larger logical-processor number. Do not fabricate CPU 23 in that case;
    // retain the last real terminal CPU instead.
    let cpu = if current < MAX_CPUS {
        current
    } else {
        (LAST_CPU.load(RELAXED) as usize).min(MAX_CPUS - 1)
    };
    force_cpu(kind, cpu, vm_error, detail)
}

pub fn force_cpu(kind: u8, cpu: usize, vm_error: u8, detail: u8) -> bool {
    if !enabled() || cpu >= MAX_CPUS {
        return false;
    }
    let sequence = RECORD_SEQUENCE.fetch_add(1, RELAXED).wrapping_add(1);
    let active_bitmap = active_bitmap();
    let Some(context) = read_cpu_context(cpu) else {
        return false;
    };
    let phase = CPU_PHASE[cpu].load(RELAXED);
    let mut flags = context.flags;
    if CPU_ACTIVE[cpu].load(ACQUIRE) != 0 {
        flags |= FLAG_ACTIVE;
    }
    if kind == KIND_VM_ENTRY_FAILURE {
        flags |= FLAG_ENTRY_FAILURE;
    }
    if vm_error != INVALID_VM_ERROR {
        flags |= FLAG_VMERR_VALID;
    }

    let record = TerminalRecord {
        kind,
        sequence,
        cpu: cpu as u8,
        phase,
        reason: context.reason,
        flags,
        vm_error,
        session: SESSION_ID.load(RELAXED),
        rip: context.rip,
        qualification: context.qualification,
        detail,
        active_bitmap,
    };
    let committed = commit_record(record);
    committed
}

pub fn record_host_fault(cpu: u8, vector: u8, rip: u64, error: u64) -> bool {
    if !enabled() {
        return false;
    }
    let mut bytes = [0u8; 16];
    bytes[0] = EMERGENCY_MAGIC;
    bytes[1] = KIND_HOST_FAULT;
    bytes[2] = cpu;
    bytes[3] = vector;
    bytes[4..12].copy_from_slice(&rip.to_le_bytes());
    bytes[12] = error as u8;
    bytes[13] = (error >> 8) as u8;
    bytes[14] = crc8(&bytes[..14]);
    bytes[15] = EMERGENCY_COMMIT;

    let Some(_guard) = try_cmos_lock() else {
        return false;
    };
    unsafe { write_cmos_unlocked(EMERGENCY_BASE + 15, 0) };
    for (index, value) in bytes[..15].iter().copied().enumerate() {
        unsafe { write_cmos_unlocked(EMERGENCY_BASE + index as u8, value) };
    }
    unsafe { write_cmos_unlocked(EMERGENCY_BASE + 15, EMERGENCY_COMMIT) };
    true
}

pub fn io_contention_count() -> u64 {
    CMOS_IO_CONTENTION.load(RELAXED)
}

fn capture_async_fatal_state() {
    let host_faults = super::host_idt::HOST_FAULT_TOTAL.load(RELAXED);
    let previous_faults = LAST_HOST_FAULT_COUNT.swap(host_faults, RELAXED);
    if host_faults > previous_faults {
        let cpu = super::host_idt::HOST_FIRST_FAULT_CPU.load(RELAXED) as u8;
        let vector = super::host_idt::HOST_FIRST_FAULT_VECTOR.load(RELAXED) as u8;
        let rip = super::host_idt::HOST_FIRST_FAULT_RIP.load(RELAXED);
        let error = super::host_idt::HOST_FIRST_FAULT_ERR.load(RELAXED);
        let _ = record_host_fault(cpu, vector, rip, error);
        let _ = force_cpu(
            KIND_HOST_FAULT,
            (cpu as usize).min(MAX_CPUS - 1),
            INVALID_VM_ERROR,
            vector,
        );
    }

    let bugchecks = super::diag::KEBUGCHECKEX_HITS
        .load(RELAXED)
        .saturating_add(super::diag::BUGCHECK_CALLBACK_FIRED.load(RELAXED));
    let previous_bugchecks = LAST_BUGCHECK_COUNT.swap(bugchecks, RELAXED);
    if bugchecks > previous_bugchecks {
        let cpu = (super::diag::KEBUGCHECKEX_HIT_CPU.load(RELAXED) as usize)
            .min(MAX_CPUS - 1);
        let detail = super::diag::KEBUGCHECKEX_HIT_ARG0.load(RELAXED) as u8;
        let _ = force_cpu(KIND_BUGCHECK, cpu, INVALID_VM_ERROR, detail);
    }
}

fn scan_stalled_handlers(now: u64, exclude: Option<usize>) {
    for cpu in 0..MAX_CPUS {
        if exclude == Some(cpu) || CPU_ACTIVE[cpu].load(ACQUIRE) == 0 {
            continue;
        }
        let progress = CPU_PROGRESS_TSC[cpu].load(ACQUIRE);
        if progress == 0 || now.wrapping_sub(progress) < HANDLER_STALL_CYCLES {
            continue;
        }
        if CPU_STALL_REPORTED[cpu]
            .compare_exchange(0, 1, ACQUIRE, RELAXED)
            .is_ok()
        {
            let age_bucket = (now.wrapping_sub(progress) >> 20).min(u8::MAX as u64) as u8;
            let _ = force_cpu(KIND_STALLED_HANDLER, cpu, INVALID_VM_ERROR, age_bucket);
        }
    }
}

fn maybe_scan_stalled_handlers(now: u64, exclude: Option<usize>) {
    let previous = LAST_STALL_SCAN_TSC.load(RELAXED);
    if now.wrapping_sub(previous) < STALL_SCAN_INTERVAL_CYCLES {
        return;
    }
    if LAST_STALL_SCAN_TSC
        .compare_exchange(previous, now, ACQUIRE, RELAXED)
        .is_ok()
    {
        scan_stalled_handlers(now, exclude);
    }
}

#[derive(Clone, Copy)]
struct CpuContext {
    flags: u8,
    reason: u8,
    rip: u64,
    qualification: u64,
}

fn read_cpu_context(cpu: usize) -> Option<CpuContext> {
    for _ in 0..3 {
        let before = CPU_CONTEXT_SEQUENCE[cpu].load(ACQUIRE);
        if before & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let context = CpuContext {
            flags: CPU_CONTEXT_FLAGS[cpu].load(RELAXED),
            reason: CPU_REASON[cpu].load(RELAXED),
            rip: CPU_RIP[cpu].load(RELAXED),
            qualification: CPU_QUALIFICATION[cpu].load(RELAXED),
        };
        if CPU_CONTEXT_SEQUENCE[cpu].load(ACQUIRE) == before {
            return Some(context);
        }
    }
    None
}

fn active_bitmap() -> u32 {
    let mut bitmap = 0u32;
    for cpu in 0..MAX_CPUS {
        if CPU_ACTIVE[cpu].load(ACQUIRE) != 0 {
            bitmap |= 1u32 << cpu;
        }
    }
    bitmap
}

fn phase_code(phase: u8) -> u8 {
    match phase {
        0x10 => 1,
        0x18 => 2,
        0x20 => 3,
        0x30 => 4,
        0x40 => 5,
        0x50 => 6,
        0x60 => 7,
        0x68 => 8,
        0x70 => 9,
        0x80 => 10,
        0x90 => 11,
        0xa0 => 12,
        0xb0 => 13,
        0xe0 => 14,
        _ => 15,
    }
}

fn is_rare_exit(reason: u64) -> bool {
    if reason & (1u64 << 31) != 0 {
        return true;
    }
    !matches!(
        reason & 0xffff,
        10 | 12 | 16 | 18 | 28 | 31 | 32 | 36 | 39 | 51 | 52
    )
}

fn commit_record(record: TerminalRecord) -> bool {
    let terminal_fatal = matches!(
        record.kind,
        KIND_STALLED_HANDLER
            | KIND_VM_ENTRY_FAILURE
            | KIND_VMRESUME_FAILURE
            | KIND_HANDLER_ERROR
            | KIND_HOST_FAULT
            | KIND_BUGCHECK
    );

    // A fatal record is the terminal observation for this boot. Check before
    // and after taking the CMOS lock: a periodic writer may race with a fatal
    // writer between the caller's latch check and lock acquisition.
    if record.kind == KIND_PERIODIC && TERMINAL_FATAL_LATCH.load(ACQUIRE) != 0 {
        return false;
    }

    let bytes = encode_record(record);
    let base = if record.sequence & 1 == 1 {
        SLOT_A_BASE
    } else {
        SLOT_B_BASE
    };
    let Some(_guard) = try_cmos_lock() else {
        return false;
    };
    if record.kind == KIND_PERIODIC && TERMINAL_FATAL_LATCH.load(ACQUIRE) != 0 {
        return false;
    }
    unsafe { write_cmos_unlocked(base + 31, 0) };
    for (index, value) in bytes[..31].iter().copied().enumerate() {
        unsafe { write_cmos_unlocked(base + index as u8, value) };
    }
    unsafe { write_cmos_unlocked(base + 31, SLOT_COMMIT) };

    // Publish the latch while the lock is still held. This closes the window
    // between committing a fatal slot and setting the latch in the caller.
    if terminal_fatal {
        TERMINAL_FATAL_LATCH.store(record.kind, RELEASE);
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalRecord {
    pub kind: u8,
    pub sequence: u16,
    pub cpu: u8,
    pub phase: u8,
    pub reason: u8,
    pub flags: u8,
    pub vm_error: u8,
    pub session: u8,
    pub rip: u64,
    pub qualification: u64,
    pub detail: u8,
    pub active_bitmap: u32,
}

impl TerminalRecord {
    pub fn active(self) -> bool {
        self.flags & FLAG_ACTIVE != 0
    }

    pub fn entry_failure(self) -> bool {
        self.flags & FLAG_ENTRY_FAILURE != 0
    }

    pub fn vm_error_valid(self) -> bool {
        self.flags & FLAG_VMERR_VALID != 0
    }
}

fn encode_record(record: TerminalRecord) -> [u8; SLOT_SIZE] {
    let mut bytes = [0u8; SLOT_SIZE];
    bytes[0] = SLOT_MAGIC;
    bytes[1] = record.kind;
    bytes[2..4].copy_from_slice(&record.sequence.to_le_bytes());
    bytes[4] = record.cpu;
    bytes[5] = record.phase;
    bytes[6] = record.reason;
    bytes[7] = record.flags;
    bytes[8] = record.vm_error;
    bytes[9] = record.session;
    bytes[10..18].copy_from_slice(&record.rip.to_le_bytes());
    bytes[18..26].copy_from_slice(&record.qualification.to_le_bytes());
    bytes[26] = record.detail;
    bytes[27] = record.active_bitmap as u8;
    bytes[28] = (record.active_bitmap >> 8) as u8;
    bytes[29] = (record.active_bitmap >> 16) as u8;
    bytes[30] = crc8(&bytes[..30]);
    bytes[31] = SLOT_COMMIT;
    bytes
}

fn decode_record(bytes: &[u8]) -> Option<TerminalRecord> {
    if bytes.len() != SLOT_SIZE
        || bytes[0] != SLOT_MAGIC
        || bytes[31] != SLOT_COMMIT
        || bytes[30] != crc8(&bytes[..30])
    {
        return None;
    }
    Some(TerminalRecord {
        kind: bytes[1],
        sequence: u16::from_le_bytes([bytes[2], bytes[3]]),
        cpu: bytes[4],
        phase: bytes[5],
        reason: bytes[6],
        flags: bytes[7],
        vm_error: bytes[8],
        session: bytes[9],
        rip: u64::from_le_bytes(bytes[10..18].try_into().ok()?),
        qualification: u64::from_le_bytes(bytes[18..26].try_into().ok()?),
        detail: bytes[26],
        active_bitmap: (bytes[27] as u32)
            | ((bytes[28] as u32) << 8)
            | ((bytes[29] as u32) << 16),
    })
}

pub fn newest_record(raw: &[u8; CMOS_BYTES]) -> Option<TerminalRecord> {
    let a = decode_record(&raw[SLOT_A_BASE as usize..SLOT_A_BASE as usize + SLOT_SIZE]);
    let b = decode_record(&raw[SLOT_B_BASE as usize..SLOT_B_BASE as usize + SLOT_SIZE]);
    match (a, b) {
        (Some(a), Some(b)) => {
            if (a.sequence.wrapping_sub(b.sequence) as i16) >= 0 {
                Some(a)
            } else {
                Some(b)
            }
        }
        (Some(record), None) | (None, Some(record)) => Some(record),
        (None, None) => None,
    }
}

pub fn previous_record() -> Option<TerminalRecord> {
    let mut raw = [0u8; CMOS_BYTES];
    copy_previous_cmos(&mut raw).then(|| newest_record(&raw)).flatten()
}

fn crc8(bytes: &[u8]) -> u8 {
    let mut crc = 0u8;
    for byte in bytes {
        crc ^= *byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(sequence: u16) -> TerminalRecord {
        TerminalRecord {
            kind: KIND_STALLED_HANDLER,
            sequence,
            cpu: 10,
            phase: 0x30,
            reason: 0x1c,
            flags: FLAG_ACTIVE | FLAG_RIP_VALID | FLAG_QUAL_VALID,
            vm_error: INVALID_VM_ERROR,
            session: 7,
            rip: 0xffff_f801_1234_5678,
            qualification: 0x13,
            detail: 42,
            active_bitmap: 0x00a4_0400,
        }
    }

    #[test]
    fn build_flags_are_explicit() {
        assert!(enabled_by_flags(Some("1"), None));
        assert!(enabled_by_flags(None, Some("1")));
        assert!(!enabled_by_flags(Some("0"), None));
        assert!(!enabled_by_flags(None, None));
    }

    #[test]
    fn record_round_trips() {
        let expected = record(42);
        let bytes = encode_record(expected);
        assert_eq!(decode_record(&bytes), Some(expected));
    }

    #[test]
    fn torn_or_corrupt_record_is_rejected() {
        let mut bytes = encode_record(record(42));
        bytes[31] = 0;
        assert_eq!(decode_record(&bytes), None);

        let mut bytes = encode_record(record(42));
        bytes[18] ^= 1;
        assert_eq!(decode_record(&bytes), None);
    }

    #[test]
    fn newest_record_handles_sequence_wrap() {
        let older = encode_record(record(u16::MAX));
        let newer = encode_record(record(0));
        let mut raw = [0u8; CMOS_BYTES];
        raw[0..SLOT_SIZE].copy_from_slice(&older);
        raw[SLOT_SIZE..SLOT_SIZE * 2].copy_from_slice(&newer);
        assert_eq!(newest_record(&raw).unwrap().sequence, 0);
    }
}
