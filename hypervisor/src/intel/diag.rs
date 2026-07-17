use {
    crate::error::HypervisorError,
    core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering::Relaxed},
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

// ---------------------------------------------------------------------------
// P2 stealth MSR counters (2026-07-09).
// Track how often EAC / anti-cheat code polls the MSRs known to be used as
// hypervisor-detection vectors. Non-zero counts point at whichever detection
// path is actively firing so we can prioritise stealth work.
// ---------------------------------------------------------------------------
pub static EFER_READ_COUNT: AtomicU64 = AtomicU64::new(0);
pub static EFER_WRITE_COUNT: AtomicU64 = AtomicU64::new(0);
pub static APERF_READ_COUNT: AtomicU64 = AtomicU64::new(0);
pub static MPERF_READ_COUNT: AtomicU64 = AtomicU64::new(0);
pub static DEBUGCTL_READ_COUNT: AtomicU64 = AtomicU64::new(0);
pub static DEBUGCTL_WRITE_COUNT: AtomicU64 = AtomicU64::new(0);
pub static LBR_STACK_READ_COUNT: AtomicU64 = AtomicU64::new(0);
pub static LBR_SAVE_COUNT: AtomicU64 = AtomicU64::new(0);
pub static LBR_RESTORE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Shadow value returned to the guest on IA32_DEBUGCTL reads. Guest writes
/// virtualise into this shadow rather than reaching hardware, so host branches
/// executed between VM-exit and VM-entry cannot corrupt the guest's LBR view.
/// Starts at 0 (LBR disabled from the guest's perspective); guest software may
/// enable it and read back exactly what it wrote.
pub static LBR_DEBUGCTL_SHADOW: AtomicU64 = AtomicU64::new(0);

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

// ---------------------------------------------------------------------------
// Per-CPU VM-exit ring (2026-07-09).
//
// The global RING_* buffers interleave exits from all CPUs, so during a freeze
// we cannot tell which CPU wrote which entry. PER_CPU_RING_* stores the last
// PER_CPU_RING_SIZE exits for each CPU independently, keyed by rdtscp AUX.
// When a CPU gets stuck in a handler / spin-loop, we can read that CPU's ring
// to see the sequence of VM-exits that led up to the freeze.
//
// The global RING_* buffers are kept for backward-compatible tooling.
// ---------------------------------------------------------------------------
pub const PER_CPU_RING_SIZE: usize = 16;
const PER_CPU_RING_LEN: usize = MAX_TRACKED_CPUS * PER_CPU_RING_SIZE;
static PER_CPU_RING_IDX: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static PER_CPU_RING_REASON: [AtomicU64; PER_CPU_RING_LEN] = [ZERO_U64; PER_CPU_RING_LEN];
static PER_CPU_RING_RIP: [AtomicU64; PER_CPU_RING_LEN] = [ZERO_U64; PER_CPU_RING_LEN];
static PER_CPU_RING_QUAL: [AtomicU64; PER_CPU_RING_LEN] = [ZERO_U64; PER_CPU_RING_LEN];
static PER_CPU_RING_RAX: [AtomicU64; PER_CPU_RING_LEN] = [ZERO_U64; PER_CPU_RING_LEN];

pub const PHASE_VMEXIT_ENTRY: u64 = 0x10;
pub const PHASE_FAST_CPUID: u64 = 0x40;
pub const PHASE_FAST_CPUID_DONE: u64 = 0x50;
pub const PHASE_FAST_RIP_ADV: u64 = 0x60;
pub const PHASE_CHECK_NMI: u64 = 0x70;
pub const PHASE_PRE_VMRESUME: u64 = 0x80;
pub const PHASE_SLOW_PATH: u64 = 0x20;
pub const PHASE_SLOW_HANDLER: u64 = 0x30;
pub const PHASE_ERROR_HANDLER: u64 = 0xE0;

// ---------------------------------------------------------------------------
// Handler-duration watchdog (2026-07-09).
//
// A stuck VM-exit handler (spinlock deadlock, tight EPT-violation loop) never
// returns to guest, so freeze_check_cpuid_stall sees the guest RIP stuck.
// This watchdog complements that with a per-CPU tally of unusually long
// handlers that *did* return, so we can spot the pattern of exit reasons that
// are approaching the freeze threshold before the actual freeze.
//
// Threshold is expressed in TSC cycles; 50M cycles ≈ 14 ms at 3.5 GHz. This
// is coarse — we do not calibrate per CPU frequency. Anything under a few
// hundred µs is invisible.
// ---------------------------------------------------------------------------
pub const HANDLER_SLOW_THRESHOLD_CYCLES: u64 = 50_000_000;

// ---------------------------------------------------------------------------
// KeBugCheckEx sentinel (2026-07-09).
//
// If EAC really is triggering `KeBugCheckEx` (as the earlier memory theory
// claimed), we should see guest RIP land inside its prologue at least once
// before the freeze. If it never does, the freeze root cause is elsewhere
// (spinlock deadlock inside HV handlers, cascaded fault, etc.).
//
// KEBUGCHECKEX_ADDR + KEBUGCHECKEX_SENTINEL are set once at driver init.
// KEBUGCHECKEX_HITS increments each VM-exit whose guest RIP falls inside
// [addr, addr + KEBUGCHECKEX_WATCH_LEN). KEBUGCHECKEX_HIT_CPU / RIP / TSC
// capture the first observed hit.
// ---------------------------------------------------------------------------
pub const KEBUGCHECKEX_WATCH_LEN: u64 = 0x100; // 256 bytes covers the prologue
pub static KEBUGCHECKEX_ADDR: AtomicU64 = AtomicU64::new(0);
pub static KEBUGCHECKEX_SENTINEL: AtomicU64 = AtomicU64::new(0);
pub static KEBUGCHECKEX_HITS: AtomicU64 = AtomicU64::new(0);
pub static KEBUGCHECKEX_HIT_CPU: AtomicU64 = AtomicU64::new(0);
pub static KEBUGCHECKEX_HIT_RIP: AtomicU64 = AtomicU64::new(0);
pub static KEBUGCHECKEX_HIT_TSC: AtomicU64 = AtomicU64::new(0);
pub static KEBUGCHECKEX_HIT_ARG0: AtomicU64 = AtomicU64::new(0);

/// Number of times `KeBugCheckCallback` actually fired. If nonzero after a
/// freeze/reboot cycle, the callback ran — meaning bug-check processing
/// reached the point where Windows dispatches driver callbacks. Together
/// with `KEBUGCHECKEX_HITS` (guest-RIP sentinel) this covers both "guest
/// executed the KeBugCheckEx prologue" and "kernel completed enough of
/// bugcheck dispatch to call our callback". Persisted to CMOS via
/// `cmos_sync_step4_state` so a hard reboot preserves the marker.
pub static BUGCHECK_CALLBACK_FIRED: AtomicU64 = AtomicU64::new(0);

/// CMOS extended offset 0x1F carries a `0xB1` magic once the bug-check
/// callback has fired. Read via `CMD_READ_CMOS_FREEZE` field 9.
const CMOS_OFF_BUGCHECK_CB_FLAG: u8 = 0x1F;
const CMOS_MAGIC_BUGCHECK_CB: u8 = 0xB1;

/// Called from `bugcheck_callback` in nt.rs. IRQL is HIGH_LEVEL, other CPUs
/// suspended, so we do the smallest possible work: increment the counter and
/// stamp a CMOS byte. Both survive the ensuing hard reboot.
pub fn note_bugcheck_callback_fired() {
    BUGCHECK_CALLBACK_FIRED.fetch_add(1, Relaxed);
    ext_cmos_write(CMOS_OFF_BUGCHECK_CB_FLAG, CMOS_MAGIC_BUGCHECK_CB);
}

/// CMOS extended offset 0x1E carries a `0xE1` magic once the EPT-execute
/// hook installed on `nt!KeBugCheckEx` has recorded a confirmed hit — i.e.
/// the guest actually entered KeBugCheckEx (before any callback dispatch,
/// so this fires strictly earlier than `BUGCHECK_CALLBACK_FIRED`). Read
/// via `CMD_READ_CMOS_FREEZE` field 10.
const CMOS_OFF_BUGCHECK_ENTRY_HOOK: u8 = 0x1E;
const CMOS_MAGIC_BUGCHECK_ENTRY_HOOK: u8 = 0xE1;

pub static BUGCHECK_ENTRY_HOOK_FIRED: AtomicU64 = AtomicU64::new(0);

/// Called from `bugcheck_hook::latch_and_uncloak` when the EPT-execute hook
/// catches guest RIP inside the KeBugCheckEx watch window. Same idea as
/// `note_bugcheck_callback_fired` but fires at bugcheck ENTRY rather than
/// at callback dispatch — the two together let us tell "bugcheck never
/// started" from "bugcheck started but hung before finishing".
pub fn note_bugcheck_entry_hook_fired() {
    BUGCHECK_ENTRY_HOOK_FIRED.fetch_add(1, Relaxed);
    ext_cmos_write(CMOS_OFF_BUGCHECK_ENTRY_HOOK, CMOS_MAGIC_BUGCHECK_ENTRY_HOOK);
}

pub fn set_kebugcheckex_sentinel(addr: u64, first_qword: u64) {
    KEBUGCHECKEX_ADDR.store(addr, Relaxed);
    KEBUGCHECKEX_SENTINEL.store(first_qword, Relaxed);
}

// ---------------------------------------------------------------------------
// CMOS Retention Experiment (Phase 0, 2026-07-12).
//
// One-shot experiment run from DriverEntry BEFORE HV virtualization begins.
// Answers three questions:
//   1. Does extended CMOS 0x20-0x2C survive warm reset / cold boot / freeze?
//   2. Does BIOS clear our bytes on boot?
//   3. Can we reliably persist a session ID and boot counter across reboots?
//
// Layout (extended CMOS ports 0x72/0x73):
//   0x20: magic (0xC3 = experiment data present)
//   0x21-0x22: boot_counter (u16 LE) — +1 every HV load
//   0x23-0x26: last_session_id (u32 LE) — previous load's this_session
//   0x27-0x2A: this_session_id (u32 LE) — random per-load (TSC low 32)
//   0x2B: completion_marker (0x00 = writing, 0x01 = complete)
//   0x2C: XOR checksum of 0x20..0x2B (with completion=0x01)
//
// Torn-write protocol:
//   1. Write completion = 0x00 (mark "writing in progress")
//   2. Write payload bytes 0x20-0x2A
//   3. Compute checksum assuming completion=0x01, write to 0x2C
//   4. Write completion = 0x01 (mark "complete")
// Reader treats completion != 0x01 or checksum mismatch as invalid.
// ---------------------------------------------------------------------------
const CMOS_RET_OFF_MAGIC: u8 = 0x20;
const CMOS_RET_OFF_COUNTER_LO: u8 = 0x21;
const CMOS_RET_OFF_COUNTER_HI: u8 = 0x22;
const CMOS_RET_OFF_LAST_SESSION_BASE: u8 = 0x23; // 0x23-0x26
const CMOS_RET_OFF_THIS_SESSION_BASE: u8 = 0x27; // 0x27-0x2A
const CMOS_RET_OFF_COMPLETION: u8 = 0x2B;
const CMOS_RET_OFF_CHECKSUM: u8 = 0x2C;
const CMOS_RET_MAGIC: u8 = 0xC3;

// Snapshot of what we READ from CMOS before overwriting — exposed via GET_CTL.
pub static CMOS_RET_PREV_MAGIC: AtomicU64 = AtomicU64::new(u64::MAX);
pub static CMOS_RET_PREV_COUNTER: AtomicU64 = AtomicU64::new(u64::MAX);
pub static CMOS_RET_PREV_LAST_SESSION: AtomicU64 = AtomicU64::new(u64::MAX);
pub static CMOS_RET_PREV_THIS_SESSION: AtomicU64 = AtomicU64::new(u64::MAX);
pub static CMOS_RET_PREV_COMPLETION: AtomicU64 = AtomicU64::new(u64::MAX);
pub static CMOS_RET_PREV_CHECKSUM_OK: AtomicU64 = AtomicU64::new(u64::MAX);

// Snapshot of what we WROTE this boot — exposed via GET_CTL.
pub static CMOS_RET_NEW_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static CMOS_RET_NEW_THIS_SESSION: AtomicU64 = AtomicU64::new(0);

// Set to 1 after the write protocol completes successfully.
pub static CMOS_RET_EXPERIMENT_RAN: AtomicU64 = AtomicU64::new(0);

/// Run the CMOS retention experiment once, at DriverEntry.
///
/// Reads previous state (populating `CMOS_RET_PREV_*` statics), then writes
/// a new state with incremented counter and fresh session id.
///
/// Safe to call before HV virtualization: uses only port I/O and no locks.
pub fn cmos_retention_experiment() {
    // ------------------------------------------------------------------
    // Phase A: read previous state.
    // ------------------------------------------------------------------
    let prev_magic = ext_cmos_read(CMOS_RET_OFF_MAGIC);
    let prev_counter_lo = ext_cmos_read(CMOS_RET_OFF_COUNTER_LO);
    let prev_counter_hi = ext_cmos_read(CMOS_RET_OFF_COUNTER_HI);
    let mut prev_last_bytes = [0u8; 4];
    let mut prev_this_bytes = [0u8; 4];
    for i in 0..4u8 {
        prev_last_bytes[i as usize] = ext_cmos_read(CMOS_RET_OFF_LAST_SESSION_BASE + i);
        prev_this_bytes[i as usize] = ext_cmos_read(CMOS_RET_OFF_THIS_SESSION_BASE + i);
    }
    let prev_completion = ext_cmos_read(CMOS_RET_OFF_COMPLETION);
    let prev_checksum = ext_cmos_read(CMOS_RET_OFF_CHECKSUM);

    let prev_counter = (prev_counter_lo as u16) | ((prev_counter_hi as u16) << 8);
    let prev_last_session = u32::from_le_bytes(prev_last_bytes);
    let prev_this_session = u32::from_le_bytes(prev_this_bytes);

    // Verify checksum against the state as it should be after a successful
    // write (completion byte contributes 0x01). Torn writes / stale data /
    // BIOS-cleared bytes will mismatch.
    let mut expected_checksum: u8 = prev_magic ^ prev_counter_lo ^ prev_counter_hi ^ 0x01; // completion (final)
    for b in prev_last_bytes.iter().chain(prev_this_bytes.iter()) {
        expected_checksum ^= *b;
    }
    let checksum_ok = expected_checksum == prev_checksum && prev_completion == 0x01;

    CMOS_RET_PREV_MAGIC.store(prev_magic as u64, Relaxed);
    CMOS_RET_PREV_COUNTER.store(prev_counter as u64, Relaxed);
    CMOS_RET_PREV_LAST_SESSION.store(prev_last_session as u64, Relaxed);
    CMOS_RET_PREV_THIS_SESSION.store(prev_this_session as u64, Relaxed);
    CMOS_RET_PREV_COMPLETION.store(prev_completion as u64, Relaxed);
    CMOS_RET_PREV_CHECKSUM_OK.store(checksum_ok as u64, Relaxed);

    // ------------------------------------------------------------------
    // Phase B: compute new state.
    // ------------------------------------------------------------------
    let is_valid_prev = prev_magic == CMOS_RET_MAGIC && checksum_ok;
    let new_counter: u16 = if is_valid_prev {
        prev_counter.wrapping_add(1)
    } else {
        1
    };
    let new_last_session: u32 = if is_valid_prev { prev_this_session } else { 0 };
    let new_this_session: u32 = rdtsc_now() as u32;

    CMOS_RET_NEW_COUNTER.store(new_counter as u64, Relaxed);
    CMOS_RET_NEW_THIS_SESSION.store(new_this_session as u64, Relaxed);

    let new_counter_lo = new_counter as u8;
    let new_counter_hi = (new_counter >> 8) as u8;
    let new_last_bytes = new_last_session.to_le_bytes();
    let new_this_bytes = new_this_session.to_le_bytes();

    // Pre-compute checksum assuming completion = 0x01 (final state).
    let mut new_checksum: u8 = CMOS_RET_MAGIC ^ new_counter_lo ^ new_counter_hi ^ 0x01;
    for b in new_last_bytes.iter().chain(new_this_bytes.iter()) {
        new_checksum ^= *b;
    }

    // ------------------------------------------------------------------
    // Phase C: torn-write-safe write protocol.
    // ------------------------------------------------------------------
    // Step 1: mark "writing in progress" so a reader after crash-during-write
    // sees completion != 0x01 and treats data as invalid.
    ext_cmos_write(CMOS_RET_OFF_COMPLETION, 0x00);
    // Step 2: payload.
    ext_cmos_write(CMOS_RET_OFF_MAGIC, CMOS_RET_MAGIC);
    ext_cmos_write(CMOS_RET_OFF_COUNTER_LO, new_counter_lo);
    ext_cmos_write(CMOS_RET_OFF_COUNTER_HI, new_counter_hi);
    for i in 0..4u8 {
        ext_cmos_write(
            CMOS_RET_OFF_LAST_SESSION_BASE + i,
            new_last_bytes[i as usize],
        );
        ext_cmos_write(
            CMOS_RET_OFF_THIS_SESSION_BASE + i,
            new_this_bytes[i as usize],
        );
    }
    // Step 3: checksum.
    ext_cmos_write(CMOS_RET_OFF_CHECKSUM, new_checksum);
    // Step 4: mark complete.
    ext_cmos_write(CMOS_RET_OFF_COMPLETION, 0x01);

    CMOS_RET_EXPERIMENT_RAN.store(1, Relaxed);

    log::info!(
        "cmos_ret: prev magic={:#04x} counter={} last={:#010x} this={:#010x} mark={:#04x} chk_ok={} | new counter={} session={:#010x}",
        prev_magic,
        prev_counter,
        prev_last_session,
        prev_this_session,
        prev_completion,
        checksum_ok as u32,
        new_counter,
        new_this_session,
    );
}

// ---------------------------------------------------------------------------
// Port 0x80 breadcrumb — hardware-visible "what handler are we in" (2026-07-15).
//
// Motherboards route port 0x80 writes to the POST code / Q-Code LED display.
// Whatever value we write last stays visible even after the CPU stops
// executing (freeze). This gives us a single-byte, out-of-band diagnostic
// that survives instant hangs — no handler needs to "finish writing" or
// "post over the network". If a board has a Q-Code display, the user reads
// the freeze state directly with their eyes.
//
// Encoding of the byte written:
//   0x00-0x7F : VM-exit basic reason (top bit clear).
//                Only reasons 0-127 fit; current SDM caps around 68 so this
//                is safe. Value visible = HV was handling that exit reason
//                when it froze (or guest resumed with that being the last
//                exit handled).
//   0x80-0x9F : host IDT fault handler entry, low 5 bits = vector (0-31).
//                Only vectors 0-31 fit; sufficient for architectural
//                exceptions. Value visible = HV took a fault while handling
//                a VM-exit (or right at a fault handler).
//   0xFC (P80_HV_ENTER)   : HV entered handle_vmexit but has not yet
//                            read EXIT_REASON. Rare/interesting window.
//   0xFD (P80_HV_LEAVE)   : reserved (devirtualize/teardown path).
//   0xFE (P80_GUEST_RESUME): reserved (right before VMRESUME).
//   0xFF                  : reserved (many boards default to 0xFF on reset).
//
// Overhead: 1 x outb, ~200-400 ns per write on typical hardware. Called
// at every VM-exit → measurable but tolerable diagnostics cost. Multi-CPU
// races produce a "last writer wins" pattern on the display, which is
// exactly the behaviour we want for a freeze-visible byte.
//
// A software shadow (PORT80_LAST) is also updated so cpuid_ping can read
// the last value via CTL id 100 (useful on boards without a Q-Code display,
// or for post-freeze CMOS-relayed capture in future phases).
// ---------------------------------------------------------------------------
pub const P80_HV_ENTER: u8 = 0xFC;
pub const P80_HV_LEAVE: u8 = 0xFD;
pub const P80_GUEST_RESUME: u8 = 0xFE;

pub static PORT80_LAST: AtomicU8 = AtomicU8::new(0);
pub static PORT80_WRITE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Write a single byte to port 0x80 (POST code) and update the software
/// shadow. Cheap enough to call at every VM-exit handler entry.
#[inline(always)]
pub fn port80(val: u8) {
    PORT80_LAST.store(val, Relaxed);
    PORT80_WRITE_COUNT.fetch_add(1, Relaxed);
    crate::utils::instructions::outb(0x80, val);
}

/// Encode a VM-exit basic reason (0-127) into port 0x80.
#[inline(always)]
pub fn port80_vmexit(basic_reason: u32) {
    port80((basic_reason & 0x7F) as u8);
}

/// Encode a host IDT fault handler entry (vector 0-31) into port 0x80.
/// Vector 32-255 external interrupts should never reach here; the host IDT
/// currently routes them through the soft default handler.
#[inline(always)]
pub fn port80_host_fault(vector: u8) {
    port80(0x80 | (vector & 0x1F));
}

// ---------------------------------------------------------------------------
// Layer 4: HV vs Guest classifier (2026-07-15).
//
// Per-CPU "am I currently inside handle_vmexit?" flag. Set at handler entry
// via RAII guard; cleared on Drop, so every Ok/Err return path (including `?`
// propagation) resets it. `fatal_vmx_failure_loop_pub()` is `-> !` and never
// drops — the flag stays 1, which correctly records "this CPU died in HV".
//
// Answers observation rule #3 in hypervisor/CLAUDE.md: distinguish
// "HV stuck" from "guest stuck" without needing a working IDT or COM logger.
//
// Read via CTL id 102 (bitmap for CPU 0-63) and 103 (popcount).
// ---------------------------------------------------------------------------
pub static HANDLER_ACTIVE: [AtomicU8; MAX_TRACKED_CPUS] =
    [const { AtomicU8::new(0) }; MAX_TRACKED_CPUS];

pub struct HandlerGuard(usize);

impl Drop for HandlerGuard {
    #[inline(always)]
    fn drop(&mut self) {
        if self.0 < MAX_TRACKED_CPUS {
            HANDLER_ACTIVE[self.0].store(0, Relaxed);
        }
    }
}

/// Mark the current CPU as inside handle_vmexit. Drop clears the flag.
#[inline(always)]
pub fn handler_enter() -> HandlerGuard {
    let cpu = super::host_idt::current_cpu_index();
    if cpu < MAX_TRACKED_CPUS {
        HANDLER_ACTIVE[cpu].store(1, Relaxed);
    }
    HandlerGuard(cpu)
}

pub fn handler_active_bitmap_lo() -> u64 {
    let mut bits = 0u64;
    let n = if MAX_TRACKED_CPUS < 64 { MAX_TRACKED_CPUS } else { 64 };
    for cpu in 0..n {
        if HANDLER_ACTIVE[cpu].load(Relaxed) != 0 {
            bits |= 1u64 << cpu;
        }
    }
    bits
}

pub fn handler_active_count() -> u64 {
    let mut n = 0u64;
    for cpu in 0..MAX_TRACKED_CPUS {
        if HANDLER_ACTIVE[cpu].load(Relaxed) != 0 {
            n += 1;
        }
    }
    n
}

// ---------------------------------------------------------------------------
// Layer 3: CMOS mirror of Layer 1 (Port 0x80) + Layer 4 (HV/Guest classifier).
//
// Phase 0 (2026-07-15) confirmed Ext CMOS 0x20-0x2C survives both warm reset
// and cold boot. Layer 3 mirrors the freeze-critical Layer 1 + 4 state to
// Ext CMOS 0x30-0x4E so a hard-reset after freeze can read back
// "who died in HV" + "last VM-exit reason on that CPU".
//
// Layout (double-buffered, 2 slots × 15 bytes, 0x30-0x4E):
//   Slot A: 0x30-0x3E    (written when sequence is odd)
//   Slot B: 0x40-0x4E    (written when sequence is even)
//
//   Per-slot:
//     +0:      magic 0x4C ('L')
//     +1..+2:  sequence u16 LE
//     +3:      PORT80_LAST snapshot
//     +4..+11: HANDLER_ACTIVE bitmap (u64 LE)
//     +12:     LAST_EXIT_REASON low 8 bits
//     +13:     popcount(bitmap)
//     +14:     XOR checksum of +0..+13
//
// Torn-write protection: writes always target only one slot per flush;
// the other slot stays intact. Reader validates each slot's checksum and
// picks the newer valid one. Freeze mid-write only invalidates that slot.
//
// Flush cadence: every LAYER3_FLUSH_INTERVAL VM-exits (64 by default). At
// ~100k exits/s the CMOS overhead is ~5% (2 outs × 15 bytes × ~1us / 64 exits).
// ---------------------------------------------------------------------------
const CMOS_L3_MAGIC: u8 = 0x4C;
const CMOS_L3_SLOT_A_BASE: u8 = 0x30;
const CMOS_L3_SLOT_B_BASE: u8 = 0x40;
const LAYER3_FLUSH_INTERVAL: u64 = 64;

static LAYER3_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static LAYER3_SEQUENCE: AtomicU64 = AtomicU64::new(0);
// Serialize concurrent flushers. Two CPUs both hitting the 64-exit boundary
// would otherwise interleave `ext_cmos_write` calls to the same slot,
// producing torn bytes even though the double-buffer scheme protects
// against freeze-in-write. If we can't acquire, we skip this cycle —
// another CPU is already writing, and the next 64-exit boundary catches up.
static LAYER3_FLUSH_LOCK: AtomicBool = AtomicBool::new(false);

fn layer3_bitmap_byte(bitmap: u64, i: usize) -> u8 {
    (bitmap >> (i * 8)) as u8
}

#[inline(always)]
pub fn layer3_maybe_flush() {
    let n = LAYER3_FLUSH_COUNT.fetch_add(1, Relaxed).wrapping_add(1);
    if n % LAYER3_FLUSH_INTERVAL != 0 {
        return;
    }
    // Try-acquire; skip if another CPU is already mid-flush.
    if LAYER3_FLUSH_LOCK
        .compare_exchange(false, true, core::sync::atomic::Ordering::Acquire, Relaxed)
        .is_err()
    {
        return;
    }
    layer3_flush();
    LAYER3_FLUSH_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

/// Force a Layer 3 flush right now, bypassing the 64-exit interval.
/// Use at Rust-reachable fatal paths (VM entry failure, pre-fatal-loop) so
/// the CMOS snapshot reflects the moment-before-crash rather than up to
/// 63 exits ago. Uses try-acquire — if another CPU is already flushing,
/// their in-progress write is fresh enough; we skip to avoid deadlock if
/// that CPU is itself frozen.
#[inline(always)]
pub fn layer3_force_flush() {
    if LAYER3_FLUSH_LOCK
        .compare_exchange(false, true, core::sync::atomic::Ordering::Acquire, Relaxed)
        .is_err()
    {
        return;
    }
    layer3_flush();
    LAYER3_FLUSH_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

fn layer3_flush() {
    let seq = LAYER3_SEQUENCE.fetch_add(1, Relaxed).wrapping_add(1) as u16;
    let base = if seq & 1 == 1 { CMOS_L3_SLOT_A_BASE } else { CMOS_L3_SLOT_B_BASE };

    let port80 = PORT80_LAST.load(Relaxed);
    let bitmap = handler_active_bitmap_lo();
    let last_exit = (LAST_EXIT_REASON.load(Relaxed) & 0xFF) as u8;
    let count = handler_active_count() as u8;

    let seq_lo = seq as u8;
    let seq_hi = (seq >> 8) as u8;

    let mut cksum = CMOS_L3_MAGIC;
    cksum ^= seq_lo;
    cksum ^= seq_hi;
    cksum ^= port80;
    for i in 0..8 {
        cksum ^= layer3_bitmap_byte(bitmap, i);
    }
    cksum ^= last_exit;
    cksum ^= count;

    // Magic first is safe under torn-write since the *other* slot stays valid.
    ext_cmos_write(base, CMOS_L3_MAGIC);
    ext_cmos_write(base + 1, seq_lo);
    ext_cmos_write(base + 2, seq_hi);
    ext_cmos_write(base + 3, port80);
    for i in 0..8 {
        ext_cmos_write(base + 4 + i as u8, layer3_bitmap_byte(bitmap, i));
    }
    ext_cmos_write(base + 12, last_exit);
    ext_cmos_write(base + 13, count);
    ext_cmos_write(base + 14, cksum);
}

struct Layer3Slot {
    seq: u16,
    port80: u8,
    bitmap: u64,
    last_exit: u8,
    count: u8,
    valid: bool,
}

fn layer3_read_slot(base: u8) -> Layer3Slot {
    let magic = ext_cmos_read(base);
    let seq_lo = ext_cmos_read(base + 1);
    let seq_hi = ext_cmos_read(base + 2);
    let port80 = ext_cmos_read(base + 3);
    let mut bitmap = 0u64;
    for i in 0..8 {
        bitmap |= (ext_cmos_read(base + 4 + i as u8) as u64) << (i * 8);
    }
    let last_exit = ext_cmos_read(base + 12);
    let count = ext_cmos_read(base + 13);
    let stored_cksum = ext_cmos_read(base + 14);

    let mut expected = magic;
    expected ^= seq_lo;
    expected ^= seq_hi;
    expected ^= port80;
    for i in 0..8 {
        expected ^= layer3_bitmap_byte(bitmap, i);
    }
    expected ^= last_exit;
    expected ^= count;

    Layer3Slot {
        seq: (seq_lo as u16) | ((seq_hi as u16) << 8),
        port80,
        bitmap,
        last_exit,
        count,
        valid: magic == CMOS_L3_MAGIC && stored_cksum == expected,
    }
}

// Cache for the last layer3_refresh_cache() call so cpuid_ping can query
// multiple fields without re-reading CMOS 30 bytes each time (and without
// tearing across a mid-read HV flush).
static LAYER3_CACHE_SLOT_ID: AtomicU8 = AtomicU8::new(0);
static LAYER3_CACHE_SEQ: AtomicU64 = AtomicU64::new(0);
static LAYER3_CACHE_PORT80: AtomicU8 = AtomicU8::new(0);
static LAYER3_CACHE_BITMAP: AtomicU64 = AtomicU64::new(0);
static LAYER3_CACHE_LAST_EXIT: AtomicU8 = AtomicU8::new(0);
static LAYER3_CACHE_COUNT: AtomicU8 = AtomicU8::new(0);
static LAYER3_CACHE_VALID: AtomicU8 = AtomicU8::new(0);

/// Read both slots from CMOS, pick the newer valid one, snapshot to cache,
/// return the slot id (0=none, 1=A, 2=B). Subsequent CTL 111-116 read cache.
fn layer3_refresh_cache() -> u8 {
    let a = layer3_read_slot(CMOS_L3_SLOT_A_BASE);
    let b = layer3_read_slot(CMOS_L3_SLOT_B_BASE);
    let (slot_id, seq, port80, bitmap, last_exit, count, valid) = match (a.valid, b.valid) {
        (true, true) => {
            if (a.seq.wrapping_sub(b.seq) as i16) >= 0 {
                (1u8, a.seq, a.port80, a.bitmap, a.last_exit, a.count, true)
            } else {
                (2u8, b.seq, b.port80, b.bitmap, b.last_exit, b.count, true)
            }
        }
        (true, false) => (1u8, a.seq, a.port80, a.bitmap, a.last_exit, a.count, true),
        (false, true) => (2u8, b.seq, b.port80, b.bitmap, b.last_exit, b.count, true),
        (false, false) => (0u8, 0, 0, 0, 0, 0, false),
    };
    LAYER3_CACHE_SLOT_ID.store(slot_id, Relaxed);
    LAYER3_CACHE_SEQ.store(seq as u64, Relaxed);
    LAYER3_CACHE_PORT80.store(port80, Relaxed);
    LAYER3_CACHE_BITMAP.store(bitmap, Relaxed);
    LAYER3_CACHE_LAST_EXIT.store(last_exit, Relaxed);
    LAYER3_CACHE_COUNT.store(count, Relaxed);
    LAYER3_CACHE_VALID.store(if valid { 1 } else { 0 }, Relaxed);
    slot_id
}

// ---------------------------------------------------------------------------
// CMOS persistence for freeze-critical Step 1-4 fields (2026-07-09).
//
// The 2026-07-09 EAC scenario test proved KEBUGCHECKEX / first-fault / total
// state stays only in RAM and vanishes on hard reboot — the exact scenario we
// need to diagnose. Extended CMOS 0x10-0x19 mirrors the RAM values; writes go
// through ext_cmos_write on state change so the port I/O is rare (fault
// events + first bugcheck hit only).
//
// Layout (extended CMOS ports 0x72/0x73):
//   0x10: magic 0xAB    — sentinel; anything else means "no diag data"
//   0x11: KEBUGCHECKEX_HITS (saturated to u8, 0/1/many)
//   0x12: HOST_FIRST_FAULT_VECTOR (0/2/8/13/14/18)
//   0x13-0x14: HOST_FAULT_TOTAL (u16 LE, saturated to 65535)
//   0x15-0x18: KEBUGCHECKEX_HIT_ARG0 (u32 LE) — bugcheck code (0x139 = ksec)
//   0x19: HOST_FIRST_FAULT_CPU
// ---------------------------------------------------------------------------
pub const CMOS_MAGIC_STEP4: u8 = 0xAB;
const CMOS_OFF_MAGIC: u8 = 0x10;
const CMOS_OFF_KBCHK_HITS: u8 = 0x11;
const CMOS_OFF_FIRST_VEC: u8 = 0x12;
const CMOS_OFF_TOTAL_LO: u8 = 0x13;
const CMOS_OFF_TOTAL_HI: u8 = 0x14;
const CMOS_OFF_KBCHK_ARG0_0: u8 = 0x15;
const CMOS_OFF_KBCHK_ARG0_1: u8 = 0x16;
const CMOS_OFF_KBCHK_ARG0_2: u8 = 0x17;
const CMOS_OFF_KBCHK_ARG0_3: u8 = 0x18;
const CMOS_OFF_FIRST_CPU: u8 = 0x19;

static CMOS_LAST_HITS: AtomicU64 = AtomicU64::new(u64::MAX);
static CMOS_LAST_VECTOR: AtomicU64 = AtomicU64::new(u64::MAX);
static CMOS_LAST_TOTAL: AtomicU64 = AtomicU64::new(u64::MAX);
static CMOS_BASELINE_LOADED: AtomicBool = AtomicBool::new(false);

/// Populate the CMOS_LAST_* shadows from whatever bytes currently sit in the
/// extended-CMOS Step 4 area. Must be called before the first VM-exit so the
/// change-detect sync does not clobber last-session's freeze data with the
/// current session's zeroed RAM baseline. Idempotent.
pub fn cmos_load_step4_baseline() {
    if CMOS_BASELINE_LOADED
        .compare_exchange(false, true, Relaxed, Relaxed)
        .is_err()
    {
        return;
    }
    let magic = ext_cmos_read(CMOS_OFF_MAGIC);
    if magic == CMOS_MAGIC_STEP4 {
        let hits = ext_cmos_read(CMOS_OFF_KBCHK_HITS) as u64;
        let vec = ext_cmos_read(CMOS_OFF_FIRST_VEC) as u64;
        let lo = ext_cmos_read(CMOS_OFF_TOTAL_LO) as u64;
        let hi = ext_cmos_read(CMOS_OFF_TOTAL_HI) as u64;
        let total = lo | (hi << 8);
        CMOS_LAST_HITS.store(hits, Relaxed);
        CMOS_LAST_VECTOR.store(vec, Relaxed);
        CMOS_LAST_TOTAL.store(total, Relaxed);
    } else {
        // No magic or corrupted — treat as clean slate.
        CMOS_LAST_HITS.store(0, Relaxed);
        CMOS_LAST_VECTOR.store(0, Relaxed);
        CMOS_LAST_TOTAL.store(0, Relaxed);
    }
}

/// Snapshot the freeze-critical Step 1-4 fields into extended CMOS. Called
/// on every VM-exit return path via `watchdog_handler_finish`; writes only
/// when a value actually changed, so the port-I/O cost is negligible during
/// normal runtime and only kicks in when something interesting fires.
#[inline]
pub fn cmos_sync_step4_state() {
    // Ensure the CMOS_LAST_* shadows reflect the actual on-disk CMOS bytes
    // before the first change-detect fires. Without this, a driver load
    // would clobber last session's freeze data on the first VM-exit.
    cmos_load_step4_baseline();

    // Only write when *this* session has recorded a nonzero event AND the
    // value differs from what CMOS holds. RAM values start at 0, so the
    // "hits == 0" guard prevents driver-load from overwriting a previous
    // session's captured freeze data with this session's zeroed baseline.
    let hits = KEBUGCHECKEX_HITS.load(Relaxed);
    if hits != 0 && hits != CMOS_LAST_HITS.load(Relaxed) {
        ext_cmos_write(CMOS_OFF_MAGIC, CMOS_MAGIC_STEP4);
        ext_cmos_write(CMOS_OFF_KBCHK_HITS, hits.min(u8::MAX as u64) as u8);
        let arg0 = KEBUGCHECKEX_HIT_ARG0.load(Relaxed);
        ext_cmos_write(CMOS_OFF_KBCHK_ARG0_0, arg0 as u8);
        ext_cmos_write(CMOS_OFF_KBCHK_ARG0_1, (arg0 >> 8) as u8);
        ext_cmos_write(CMOS_OFF_KBCHK_ARG0_2, (arg0 >> 16) as u8);
        ext_cmos_write(CMOS_OFF_KBCHK_ARG0_3, (arg0 >> 24) as u8);
        CMOS_LAST_HITS.store(hits, Relaxed);
    }
    let vector = super::host_idt::HOST_FIRST_FAULT_VECTOR.load(Relaxed);
    if vector != 0 && vector != CMOS_LAST_VECTOR.load(Relaxed) {
        ext_cmos_write(CMOS_OFF_MAGIC, CMOS_MAGIC_STEP4);
        ext_cmos_write(CMOS_OFF_FIRST_VEC, vector.min(u8::MAX as u64) as u8);
        let cpu = super::host_idt::HOST_FIRST_FAULT_CPU.load(Relaxed);
        ext_cmos_write(CMOS_OFF_FIRST_CPU, cpu.min(u8::MAX as u64) as u8);
        CMOS_LAST_VECTOR.store(vector, Relaxed);
    }
    let total = super::host_idt::HOST_FAULT_TOTAL.load(Relaxed);
    if total != 0 && total != CMOS_LAST_TOTAL.load(Relaxed) {
        ext_cmos_write(CMOS_OFF_MAGIC, CMOS_MAGIC_STEP4);
        let clamped = total.min(u16::MAX as u64) as u16;
        ext_cmos_write(CMOS_OFF_TOTAL_LO, clamped as u8);
        ext_cmos_write(CMOS_OFF_TOTAL_HI, (clamped >> 8) as u8);
        CMOS_LAST_TOTAL.store(total, Relaxed);
    }
}

/// Read the extended-CMOS Step 1-4 snapshot.
///
/// Field packing so the value fits in a single u64 return:
///   field 6: `magic(8) | hits(8) | vec(8) | cpu(8) | total_lo(8) | total_hi(8)`
///   field 7: full `arg0` u32
/// Callers verify `field6 & 0xFF == CMOS_MAGIC_STEP4` before trusting the rest.
pub fn cmos_read_step4(field: u64) -> u64 {
    match field {
        6 => {
            let magic = ext_cmos_read(CMOS_OFF_MAGIC) as u64;
            let hits = ext_cmos_read(CMOS_OFF_KBCHK_HITS) as u64;
            let vec = ext_cmos_read(CMOS_OFF_FIRST_VEC) as u64;
            let cpu = ext_cmos_read(CMOS_OFF_FIRST_CPU) as u64;
            let total_lo = ext_cmos_read(CMOS_OFF_TOTAL_LO) as u64;
            let total_hi = ext_cmos_read(CMOS_OFF_TOTAL_HI) as u64;
            magic
                | (hits << 8)
                | (vec << 16)
                | (cpu << 24)
                | (total_lo << 32)
                | (total_hi << 40)
        }
        7 => {
            let b0 = ext_cmos_read(CMOS_OFF_KBCHK_ARG0_0) as u64;
            let b1 = ext_cmos_read(CMOS_OFF_KBCHK_ARG0_1) as u64;
            let b2 = ext_cmos_read(CMOS_OFF_KBCHK_ARG0_2) as u64;
            let b3 = ext_cmos_read(CMOS_OFF_KBCHK_ARG0_3) as u64;
            b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        }
        9 => ext_cmos_read(CMOS_OFF_BUGCHECK_CB_FLAG) as u64,
        10 => ext_cmos_read(CMOS_OFF_BUGCHECK_ENTRY_HOOK) as u64,
        8 => {
            // Clear all Step 1-4 CMOS bytes and reset the change-detect shadows
            // so the next boot starts from a clean slate.
            ext_cmos_write(CMOS_OFF_MAGIC, 0);
            ext_cmos_write(CMOS_OFF_KBCHK_HITS, 0);
            ext_cmos_write(CMOS_OFF_FIRST_VEC, 0);
            ext_cmos_write(CMOS_OFF_TOTAL_LO, 0);
            ext_cmos_write(CMOS_OFF_TOTAL_HI, 0);
            ext_cmos_write(CMOS_OFF_KBCHK_ARG0_0, 0);
            ext_cmos_write(CMOS_OFF_KBCHK_ARG0_1, 0);
            ext_cmos_write(CMOS_OFF_KBCHK_ARG0_2, 0);
            ext_cmos_write(CMOS_OFF_KBCHK_ARG0_3, 0);
            ext_cmos_write(CMOS_OFF_FIRST_CPU, 0);
            ext_cmos_write(CMOS_OFF_BUGCHECK_ENTRY_HOOK, 0);
            ext_cmos_write(CMOS_OFF_BUGCHECK_CB_FLAG, 0);
            CMOS_LAST_HITS.store(u64::MAX, Relaxed);
            CMOS_LAST_VECTOR.store(u64::MAX, Relaxed);
            CMOS_LAST_TOTAL.store(u64::MAX, Relaxed);
            0
        }
        _ => u64::MAX,
    }
}

/// Called from the VM-exit prologue with the current guest RIP and RCX. If
/// RIP lies inside the watched KeBugCheckEx prologue, record a hit. RCX
/// carries the bugcheck code in the Windows x64 calling convention, so
/// capturing it tells us *which* bugcheck code was raised (0x139 is the
/// KERNEL_SECURITY_CHECK_FAILURE we saw in Windows event log).
#[inline]
pub fn observe_guest_rip_for_bugcheck(guest_rip: u64, guest_rcx: u64) {
    let base = KEBUGCHECKEX_ADDR.load(Relaxed);
    if base == 0 {
        return;
    }
    let end = base.wrapping_add(KEBUGCHECKEX_WATCH_LEN);
    if guest_rip < base || guest_rip >= end {
        return;
    }
    let count = KEBUGCHECKEX_HITS.fetch_add(1, Relaxed);
    // Capture only the first hit's context so cascades do not overwrite it.
    if count == 0 {
        KEBUGCHECKEX_HIT_CPU.store(rdtscp_aux() as u64, Relaxed);
        KEBUGCHECKEX_HIT_RIP.store(guest_rip, Relaxed);
        KEBUGCHECKEX_HIT_TSC.store(rdtsc_now(), Relaxed);
        KEBUGCHECKEX_HIT_ARG0.store(guest_rcx, Relaxed);
    }
}
static HANDLER_START_TSC: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static HANDLER_LAST_EXIT_REASON: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static HANDLER_MAX_DELTA: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static HANDLER_MAX_DELTA_REASON: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static HANDLER_SLOW_COUNT: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static HANDLER_LAST_SLOW_REASON: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static HANDLER_LAST_SLOW_RIP: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];
static HANDLER_LAST_SLOW_DELTA: [AtomicU64; MAX_TRACKED_CPUS] = [ZERO_U64; MAX_TRACKED_CPUS];

/// Record VM-exit handler start. Called from `handle_vmexit` prologue with
/// the TSC snapshot and current exit reason (from VMCS). Same CPU can call
/// this recursively during nested VM-exits; only the newest start survives.
#[inline]
pub fn watchdog_handler_start(tsc: u64, exit_reason: u64) {
    let cpu = rdtscp_aux() as usize % MAX_TRACKED_CPUS;
    HANDLER_START_TSC[cpu].store(tsc, Relaxed);
    HANDLER_LAST_EXIT_REASON[cpu].store(exit_reason, Relaxed);
}

/// Compute handler duration and update per-CPU watchdog counters. Called
/// right before VMRESUME (e.g. from `check_pending_nmi`) so the delta
/// captures the entire time in host mode for this VM-exit.
#[inline]
pub fn watchdog_handler_finish(guest_rip: u64) {
    let cpu = rdtscp_aux() as usize % MAX_TRACKED_CPUS;
    let start = HANDLER_START_TSC[cpu].load(Relaxed);
    if start == 0 {
        return;
    }
    let now = rdtsc_now();
    let delta = now.wrapping_sub(start);
    let reason = HANDLER_LAST_EXIT_REASON[cpu].load(Relaxed);
    // Update per-CPU max (best-effort; racy across nested exits).
    if delta > HANDLER_MAX_DELTA[cpu].load(Relaxed) {
        HANDLER_MAX_DELTA[cpu].store(delta, Relaxed);
        HANDLER_MAX_DELTA_REASON[cpu].store(reason, Relaxed);
    }
    if delta >= HANDLER_SLOW_THRESHOLD_CYCLES {
        HANDLER_SLOW_COUNT[cpu].fetch_add(1, Relaxed);
        HANDLER_LAST_SLOW_REASON[cpu].store(reason, Relaxed);
        HANDLER_LAST_SLOW_RIP[cpu].store(guest_rip, Relaxed);
        HANDLER_LAST_SLOW_DELTA[cpu].store(delta, Relaxed);
    }
    // Clear start so nested/spurious calls do not double-count.
    HANDLER_START_TSC[cpu].store(0, Relaxed);

    // Persist freeze-critical Step 1-4 state to CMOS so a hard reboot can
    // still recover the "who died first" answer we lost on 2026-07-09.
    cmos_sync_step4_state();
}

/// Read one field of watchdog state for a given CPU.
///
/// Fields:
///  0 -> HANDLER_MAX_DELTA (TSC cycles)
///  1 -> HANDLER_MAX_DELTA_REASON
///  2 -> HANDLER_SLOW_COUNT
///  3 -> HANDLER_LAST_SLOW_REASON
///  4 -> HANDLER_LAST_SLOW_RIP
///  5 -> HANDLER_LAST_SLOW_DELTA
///  6 -> HANDLER_START_TSC (nonzero => currently inside a handler)
///  7 -> HANDLER_LAST_EXIT_REASON
pub fn watchdog_field(cpu: u64, field: u64) -> u64 {
    let c = cpu as usize;
    if c >= MAX_TRACKED_CPUS {
        return u64::MAX;
    }
    match field {
        0 => HANDLER_MAX_DELTA[c].load(Relaxed),
        1 => HANDLER_MAX_DELTA_REASON[c].load(Relaxed),
        2 => HANDLER_SLOW_COUNT[c].load(Relaxed),
        3 => HANDLER_LAST_SLOW_REASON[c].load(Relaxed),
        4 => HANDLER_LAST_SLOW_RIP[c].load(Relaxed),
        5 => HANDLER_LAST_SLOW_DELTA[c].load(Relaxed),
        6 => HANDLER_START_TSC[c].load(Relaxed),
        7 => HANDLER_LAST_EXIT_REASON[c].load(Relaxed),
        _ => u64::MAX,
    }
}

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
/// The counter is still updated so `GET_CTL 4` can surface long-idle CPUs for
/// diagnostics, but we never return true — the automatic NMI-injection path
/// turned out to be a self-inflicted BSOD 0x80 NMI_HARDWARE_FAILURE on any
/// CPU that legitimately stayed in a HLT/MWAIT idle loop long enough (~9-15s
/// of uninterrupted deep C-state) to trip the 200-fire threshold. Every
/// silent freeze we chased for weeks may have been us NMI-ing our own guest.
/// A future real-freeze detector needs a signal that can distinguish idle
/// from stall (e.g. VM-exit rate on the same CPU), not just guest RIP.
#[inline]
pub fn cpu_record_timer_rip(rip: u64) -> bool {
    let cpu = rdtscp_aux() as usize & 0x3F;
    let prev = CPU_TIMER_RIP[cpu].swap(rip, Relaxed);
    if (prev >> 7) == (rip >> 7) {
        CPU_TIMER_RIP_COUNT[cpu].fetch_add(1, Relaxed);
    } else {
        CPU_TIMER_RIP_COUNT[cpu].store(0, Relaxed);
    }
    false
}

// ---------------------------------------------------------------------------
// Smart freeze detector + NMI inject (2026-07-16).
//
// Purpose: when >=N guest CPUs are simultaneously stuck at high IRQL with
// interrupts disabled for >=1 second, inject NMI into guest so Windows'
// KiNmiInterrupt → NMICrashDump=1 → KeBugCheckEx(0x80) → MEMORY.DMP path
// fires. This produces a full kernel memory dump that WinDbg can crack open
// post-reboot, giving us EVERY CPU's kernel stack at freeze time — orders of
// magnitude more data than any CMOS-based approach.
//
// Compared to the 2026-07-12-disabled `cpu_record_timer_rip` auto-NMI path:
//   old:  only "same RIP for 200 preempt timer hits". Idle CPUs in HLT loop
//         legitimately match this → self-inflicted BSOD 0x80.
//   new:  same RIP AND guest CR8 >=2 AND guest RFLAGS.IF ==0. Idle CPUs sit
//         at CR8=0 with IF=1, filtered out. Only real deadlocks (spin at
//         DPC_LEVEL / IPI_LEVEL with interrupts off) match.
//
// Extra safeguards:
//   - Armed only after `FREEZE_ARM_DELAY_TICKS` preempt timer hits (~10s) to
//     avoid firing during HV boot / Windows post-load quiescence noise.
//   - Requires >=`FREEZE_MIN_STUCK_CPUS` marked stuck simultaneously — a
//     single CPU legitimately at high IRQL doesn't count.
//   - One-shot: `FREEZE_NMI_FIRED` compare-exchange guarantees exactly one
//     CPU injects. Post-BSOD reboot re-arms the whole thing.
//   - Stamps Ext CMOS 0x2D = 0xFD before injecting so a post-reboot cpuid_ping
//     can distinguish "we triggered the BSOD" from "unrelated bugcheck".
// ---------------------------------------------------------------------------

/// Preempt timer fires ~every 50ms (VMX_PREEMPTION_TIMER_VALUE = 0x60_0000).
/// 20 hits ≈ 1 second of guest being stuck at same 128-byte RIP block.
const FREEZE_STUCK_THRESHOLD: u64 = 20;
/// Minimum simultaneously-stuck CPUs before we inject. 4 is high enough that
/// single-CPU legitimate high-IRQL work (rare) won't trigger.
const FREEZE_MIN_STUCK_CPUS: u32 = 4;
/// Delay after HV load before arming. 40 preempt timer hits (global counter)
/// = ~1s across 32 CPUs. Boot-time freezes fire within seconds of game load,
/// so we can't afford a long arm delay.
const FREEZE_ARM_DELAY_TICKS: u64 = 40;
/// Ext CMOS 0x2D — marked 0xFD when the detector actually fires an NMI.
/// Post-reboot cpuid_ping reads this to prove the BSOD (if any) came from
/// us and not from an unrelated Windows bugcheck.
const CMOS_OFF_FREEZE_DETECTED: u8 = 0x2D;
const CMOS_MAGIC_FREEZE_DETECTED: u8 = 0xFD;
/// Ext CMOS 0x2E — persistent mirror of the peak simultaneously-stuck CPU
/// count seen during the last boot. If detector never fired but this shows
/// e.g. 3, we know we came within one CPU of the threshold — useful for
/// tuning FREEZE_MIN_STUCK_CPUS post-mortem.
const CMOS_OFF_FREEZE_PEAK: u8 = 0x2E;

static FREEZE_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);
static CPU_STUCK_MARKED: [AtomicU8; MAX_TRACKED_CPUS] =
    [const { AtomicU8::new(0) }; MAX_TRACKED_CPUS];
static FREEZE_NMI_FIRED: AtomicU64 = AtomicU64::new(0);
static CPU_WANT_NMI: [AtomicU8; MAX_TRACKED_CPUS] =
    [const { AtomicU8::new(0) }; MAX_TRACKED_CPUS];
/// Peak simultaneously-stuck CPU count observed during this boot (RAM).
/// Mirror to CMOS 0x2E on every increase so post-reboot analysis can see
/// how close we got to threshold even if we never fired.
static FREEZE_MAX_STUCK_SEEN: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Layer 6: persistent per-CPU snapshot (2026-07-16).
//
// Follows CLAUDE.md observation rule #1: "平时高频写". Every N vmexits per
// CPU, flush this CPU's sequence + last exit reason to CMOS. On boot,
// snap_capture_prev_boot() copies the CMOS contents into RAM statics BEFORE
// any this-boot flush overwrites them — so post-freeze the reader has full
// visibility into PREV BOOT's last state per CPU.
//
// Judgment: compare each CPU's sequence to global sequence at time of
// snapshot. Gap between them = "how many exits behind this CPU is".
//   gap == 0: CPU was up-to-date at snapshot time
//   gap small (< ~50): CPU had recent activity
//   gap huge: CPU stopped exiting long before snapshot — probably stuck
// The CPU with the LARGEST gap died first.
//
// CMOS layout (Ext CMOS ports 0x72/0x73):
//   0x2D:      magic 0xA5 (valid snapshot present)
//   0x2E-0x2F: global sequence low, high (16-bit)
//   0x30-0x4E: Layer 3 (DON'T TOUCH — existing double-buffer)
//   0x50-0x67: per-CPU sequence low byte (24 CPUs)
//   0x68-0x7F: per-CPU last exit reason (24 CPUs)
// ---------------------------------------------------------------------------

const SNAP_CMOS_MAGIC_OFF: u8 = 0x2D;
const SNAP_CMOS_MAGIC: u8 = 0xA5;
const SNAP_CMOS_SEQ_LO_OFF: u8 = 0x2E;
const SNAP_CMOS_SEQ_HI_OFF: u8 = 0x2F;
const SNAP_CMOS_CPU_SEQ_BASE: u8 = 0x50;
const SNAP_CMOS_CPU_REASON_BASE: u8 = 0x68;
/// Only track first 24 CPUs — i7-13700KF has 24 logical (8P HT + 16E) and
/// the CMOS budget (0x50-0x7F = 48 bytes) fits exactly 24 CPUs at 2 bytes
/// per CPU. Untracked CPUs still bump global sequence and RAM shadow but
/// don't flush to CMOS.
pub const SNAP_MAX_CPUS: usize = 24;
/// Flush every N-th vmexit per CPU. Was 4 originally; bumped to 16 on
/// 2026-07-16 after boot-freeze happened faster with Layer 6 than without,
/// suggesting CMOS I/O throughput (~20μs per flush) added enough handler
/// latency to worsen the freeze race. 16 = 4x less CMOS traffic while
/// still tight enough to capture pre-freeze state (16 vmexits ≈ few ms
/// at typical rates).
const SNAP_FLUSH_INTERVAL: u64 = 16;

/// Global monotonic sequence — bumped on every snap_flush attempt.
static SNAP_GLOBAL_SEQ: AtomicU64 = AtomicU64::new(0);
/// Per-CPU vmexit counter — used to gate flush frequency.
static SNAP_CPU_VMEXIT_COUNT: [AtomicU64; SNAP_MAX_CPUS] =
    [ZERO_U64; SNAP_MAX_CPUS];
/// RAM shadow of last-flushed sequence per CPU (for CTL 143+cpu queries
/// during this boot).
static SNAP_CPU_LAST_FLUSH_SEQ: [AtomicU64; SNAP_MAX_CPUS] =
    [ZERO_U64; SNAP_MAX_CPUS];
/// RAM shadow of last-flushed exit reason per CPU.
static SNAP_CPU_LAST_REASON: [AtomicU64; SNAP_MAX_CPUS] =
    [ZERO_U64; SNAP_MAX_CPUS];
/// TRY-lock for the multi-byte CMOS write sequence. Non-blocking: if
/// contended, the losing CPU just skips this flush. Missing occasional
/// flushes is fine because the snapshot pattern is idempotent — the NEXT
/// successful flush from this CPU catches up.
static SNAP_FLUSH_LOCK: AtomicBool = AtomicBool::new(false);
/// True iff snap_capture_prev_boot() found a valid PREV BOOT snapshot in
/// CMOS at driver_entry time. Exposed via CTL 140.
static SNAP_PREV_VALID: AtomicU64 = AtomicU64::new(0);
/// PREV BOOT's global sequence (16-bit, captured from CMOS 0x2E-0x2F).
/// Exposed via CTL 141.
static SNAP_PREV_GLOBAL_SEQ: AtomicU64 = AtomicU64::new(0);
/// PREV BOOT per-CPU last-flushed sequence. Exposed via CTL 142+cpu.
static SNAP_PREV_CPU_SEQ: [AtomicU64; SNAP_MAX_CPUS] =
    [ZERO_U64; SNAP_MAX_CPUS];
/// PREV BOOT per-CPU last exit reason. Exposed via CTL 166+cpu.
static SNAP_PREV_CPU_REASON: [AtomicU64; SNAP_MAX_CPUS] =
    [ZERO_U64; SNAP_MAX_CPUS];

// ---------------------------------------------------------------------------
// Layer 6+ rare-exit RING (2026-07-16, relocated 3rd time to Ext CMOS 0x00-0x0F).
//
// History:
//  - Attempt 1 (Ext CMOS 0x30-0x4F): collided with Layer 3 slot A/B — zero captures.
//  - Attempt 2 (Std CMOS 0x40-0x55): BIOS clears std CMOS 0x40+ on reboot on
//    this system (verified: live write worked, prev-boot magic missing).
//  - Attempt 3 (Ext CMOS 0x00-0x0F, THIS): 16 bytes, previously reserved for
//    the DEAD `cmos_write_rip` function. Ext CMOS 0x00-0x0F is proven
//    persistent (old single-slot rare-exit tracker at 0x00-0x08 captured
//    VMCALL/INIT across freeze+RST). 2 slots × 6 bytes + 4-byte header.
//
// Layout:
//   0x00: magic 0xD6 = valid ring present
//   0x01: head (0..1, next write slot)
//   0x02: count (saturating u8, total rare exits observed)
//   0x03: reserved
//   0x04-0x0F: 2 slots × 6 bytes each
//     slot i base = 0x04 + i * 6
//       +0: CPU index
//       +1: exit reason low byte
//       +2..5: RIP low 32 bits (little-endian)
// ---------------------------------------------------------------------------

const RARE_RING_MAGIC_OFF: u8 = 0x00;
const RARE_RING_MAGIC: u8 = 0xD6;
const RARE_RING_HEAD_OFF: u8 = 0x01;
const RARE_RING_COUNT_OFF: u8 = 0x02;
const RARE_RING_SLOT_BASE: u8 = 0x04;
const RARE_RING_SLOT_SIZE: u8 = 6;
pub const RARE_RING_SLOTS: usize = 2;

/// Count of rare exits this boot — sanity check "did any rare exit happen at
/// all". Zero = no rare event was observed → freeze isn't triggered by any
/// exit reason outside the common set. Non-zero = ring has data.
static RARE_TOTAL_COUNT: AtomicU64 = AtomicU64::new(0);

/// THIS BOOT ring cursor (write head index into CMOS ring, 0..RARE_RING_SLOTS).
static RARE_RING_HEAD: AtomicU64 = AtomicU64::new(0);

/// PREV BOOT ring — populated by snap_capture_prev_boot.
static RARE_RING_PREV_MAGIC_OK: AtomicU64 = AtomicU64::new(0);
static RARE_RING_PREV_HEAD: AtomicU64 = AtomicU64::new(0);
static RARE_RING_PREV_COUNT: AtomicU64 = AtomicU64::new(0);
static RARE_RING_PREV_CPU: [AtomicU64; RARE_RING_SLOTS] =
    [ZERO_U64; RARE_RING_SLOTS];
static RARE_RING_PREV_REASON: [AtomicU64; RARE_RING_SLOTS] =
    [ZERO_U64; RARE_RING_SLOTS];
static RARE_RING_PREV_RIP: [AtomicU64; RARE_RING_SLOTS] =
    [ZERO_U64; RARE_RING_SLOTS];
static RARE_RING_PREV_SEQ_LO: [AtomicU64; RARE_RING_SLOTS] =
    [ZERO_U64; RARE_RING_SLOTS];

/// Called from snap_flush after common-exit early return. Decides whether
/// this exit is "rare" (worth persisting separately) and if so writes the
/// details into the ring at CMOS 0x30-0x4F. Reuses SNAP_FLUSH_LOCK.
#[inline]
fn is_common_exit(reason: u64) -> bool {
    matches!(
        reason,
        10  // CPUID — extremely common with EAC probing
        | 12 // HLT — idle CPUs
        | 16 // RDTSC
        | 31 // RDMSR
        | 32 // WRMSR
        | 36 // MWAIT
        | 39 // MONITOR
        | 51 // RDTSCP
        | 52 // Preempt timer
    )
}

#[inline]
fn snap_flush_rare(exit_reason: u64, cpu: usize, _seq: u64) {
    if is_common_exit(exit_reason) {
        return;
    }
    RARE_TOTAL_COUNT.fetch_add(1, Relaxed);
    let rip = super::support::vmread_checked(x86::vmx::vmcs::guest::RIP).unwrap_or(0);

    // Advance write head (mod RARE_RING_SLOTS). Lock is held by caller.
    let head = (RARE_RING_HEAD.load(Relaxed) as usize) % RARE_RING_SLOTS;
    let next = (head + 1) % RARE_RING_SLOTS;
    RARE_RING_HEAD.store(next as u64, Relaxed);

    // Std CMOS 0x70/0x71 write path (Ext CMOS 0x30-0x4F collides with
    // Layer 3 double-buffer — first attempt captured zero due to interleave).
    let base = RARE_RING_SLOT_BASE + (head as u8) * RARE_RING_SLOT_SIZE;
    ext_cmos_write(base, cpu as u8);
    ext_cmos_write(base + 1, (exit_reason & 0xFF) as u8);
    for b in 0..4u8 {
        ext_cmos_write(base + 2 + b, ((rip >> (b * 8)) & 0xFF) as u8);
    }

    // Update header: head advances, count saturates at 0xFF, magic (re)set.
    ext_cmos_write(RARE_RING_HEAD_OFF, next as u8);
    let total = RARE_TOTAL_COUNT.load(Relaxed);
    let count_stored = if total > 0xFF { 0xFF } else { total as u8 };
    ext_cmos_write(RARE_RING_COUNT_OFF, count_stored);
    ext_cmos_write(RARE_RING_MAGIC_OFF, RARE_RING_MAGIC);
}

/// Capture prev-boot rare-exit ring from Ext CMOS 0x00-0x0F. Called from
/// snap_capture_prev_boot after the per-CPU capture.
fn snap_capture_prev_rare() {
    let magic = ext_cmos_read(RARE_RING_MAGIC_OFF);
    if magic != RARE_RING_MAGIC {
        RARE_RING_PREV_MAGIC_OK.store(0, Relaxed);
        return;
    }
    RARE_RING_PREV_MAGIC_OK.store(1, Relaxed);
    RARE_RING_PREV_HEAD.store(ext_cmos_read(RARE_RING_HEAD_OFF) as u64, Relaxed);
    RARE_RING_PREV_COUNT.store(ext_cmos_read(RARE_RING_COUNT_OFF) as u64, Relaxed);

    for slot in 0..RARE_RING_SLOTS {
        let base = RARE_RING_SLOT_BASE + (slot as u8) * RARE_RING_SLOT_SIZE;
        RARE_RING_PREV_CPU[slot].store(ext_cmos_read(base) as u64, Relaxed);
        RARE_RING_PREV_REASON[slot].store(ext_cmos_read(base + 1) as u64, Relaxed);
        let mut rip = 0u64;
        for b in 0..4u8 {
            rip |= (ext_cmos_read(base + 2 + b) as u64) << (b * 8);
        }
        RARE_RING_PREV_RIP[slot].store(rip, Relaxed);
        // Slot has no per-slot seq_lo (space tight); ordering comes from head.
        RARE_RING_PREV_SEQ_LO[slot].store(0, Relaxed);
    }
}

/// Called ONCE from driver_entry BEFORE any snap_flush() can write to CMOS.
/// Copies the previous-boot snapshot from CMOS into RAM statics so post-
/// mortem readers can inspect PREV BOOT state even after this-boot flushes
/// overwrite CMOS. Idempotent — safe if magic is absent (just marks prev
/// as invalid).
pub fn snap_capture_prev_boot() {
    let magic = ext_cmos_read(SNAP_CMOS_MAGIC_OFF);
    if magic != SNAP_CMOS_MAGIC {
        SNAP_PREV_VALID.store(0, Relaxed);
        return;
    }
    let seq_lo = ext_cmos_read(SNAP_CMOS_SEQ_LO_OFF) as u64;
    let seq_hi = ext_cmos_read(SNAP_CMOS_SEQ_HI_OFF) as u64;
    SNAP_PREV_GLOBAL_SEQ.store(seq_lo | (seq_hi << 8), Relaxed);
    for i in 0..SNAP_MAX_CPUS {
        SNAP_PREV_CPU_SEQ[i].store(
            ext_cmos_read(SNAP_CMOS_CPU_SEQ_BASE + i as u8) as u64,
            Relaxed,
        );
        SNAP_PREV_CPU_REASON[i].store(
            ext_cmos_read(SNAP_CMOS_CPU_REASON_BASE + i as u8) as u64,
            Relaxed,
        );
    }
    SNAP_PREV_VALID.store(1, Relaxed);

    // Also capture the rare-exit tracker from CMOS 0x00-0x08.
    snap_capture_prev_rare();
}

/// Called from EVERY vmexit prologue (in handle_vmexit). Every Nth call for
/// this CPU actually flushes to CMOS; between flushes only RAM shadow is
/// updated. `exit_reason` is the basic exit reason from `EXIT_REASON`.
#[inline]
pub fn snap_flush(exit_reason: u64) {
    let cpu = super::host_idt::current_cpu_index();
    if cpu >= SNAP_MAX_CPUS {
        return;
    }

    let per_cpu_count = SNAP_CPU_VMEXIT_COUNT[cpu]
        .fetch_add(1, Relaxed)
        .wrapping_add(1);
    let is_periodic = per_cpu_count % SNAP_FLUSH_INTERVAL == 0;
    let is_rare = !is_common_exit(exit_reason);

    // Early-out only if BOTH gates fail — rare exits always attempt a flush
    // so we don't miss the one that might trigger freeze.
    if !is_periodic && !is_rare {
        return;
    }

    let seq = SNAP_GLOBAL_SEQ.fetch_add(1, Relaxed).wrapping_add(1);

    if SNAP_FLUSH_LOCK
        .compare_exchange(false, true, core::sync::atomic::Ordering::Acquire, Relaxed)
        .is_err()
    {
        return;
    }

    if is_periodic {
        ext_cmos_write(SNAP_CMOS_MAGIC_OFF, SNAP_CMOS_MAGIC);
        ext_cmos_write(SNAP_CMOS_SEQ_LO_OFF, (seq & 0xFF) as u8);
        ext_cmos_write(SNAP_CMOS_SEQ_HI_OFF, ((seq >> 8) & 0xFF) as u8);
        ext_cmos_write(SNAP_CMOS_CPU_SEQ_BASE + cpu as u8, (seq & 0xFF) as u8);
        ext_cmos_write(
            SNAP_CMOS_CPU_REASON_BASE + cpu as u8,
            (exit_reason & 0xFF) as u8,
        );
        SNAP_CPU_LAST_FLUSH_SEQ[cpu].store(seq, Relaxed);
        SNAP_CPU_LAST_REASON[cpu].store(exit_reason, Relaxed);
    }

    if is_rare {
        snap_flush_rare(exit_reason, cpu, seq);
    }

    SNAP_FLUSH_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

/// Called from the preempt-timer VM-exit handler AFTER slow-path reads have
/// populated guest RIP/RFLAGS in `guest_registers`. `cr8` is read live by the
/// caller from the host CR8 register (which reflects guest's last CR8 value
/// since we don't intercept CR8 access — see msr_bitmap / secondary ctrls).
#[inline]
pub fn preempt_timer_check_freeze(rip: u64, rflags: u64, cr8: u64) {
    let cpu = super::host_idt::current_cpu_index();
    if cpu >= MAX_TRACKED_CPUS {
        return;
    }

    let tick = FREEZE_TICK_COUNTER.fetch_add(1, Relaxed).wrapping_add(1);
    if tick < FREEZE_ARM_DELAY_TICKS {
        return;
    }

    let if_flag = (rflags >> 9) & 1;
    let is_stuck_condition = cr8 >= 2 && if_flag == 0;

    if !is_stuck_condition {
        CPU_TIMER_RIP_COUNT[cpu].store(0, Relaxed);
        CPU_STUCK_MARKED[cpu].store(0, Relaxed);
        return;
    }

    // Same 128-byte RIP block? cpu_record_timer_rip already updated CPU_TIMER_RIP
    // for us (caller invokes it just before this function). Just look at the
    // count it accumulated.
    let count = CPU_TIMER_RIP_COUNT[cpu].load(Relaxed);
    if count >= FREEZE_STUCK_THRESHOLD {
        CPU_STUCK_MARKED[cpu].store(1, Relaxed);
    }

    if FREEZE_NMI_FIRED.load(Relaxed) != 0 {
        return;
    }

    let mut marked = 0u32;
    for i in 0..MAX_TRACKED_CPUS {
        if CPU_STUCK_MARKED[i].load(Relaxed) != 0 {
            marked = marked.saturating_add(1);
        }
    }

    // Track peak simultaneously-stuck count for post-mortem tuning. Persist
    // to CMOS 0x2E only when we actually see a NEW peak to minimise CMOS
    // I/O overhead during hot path.
    let prev_peak = FREEZE_MAX_STUCK_SEEN.load(Relaxed);
    if (marked as u64) > prev_peak {
        FREEZE_MAX_STUCK_SEEN.store(marked as u64, Relaxed);
        ext_cmos_write(CMOS_OFF_FREEZE_PEAK, marked.min(u8::MAX as u32) as u8);
    }

    if marked >= FREEZE_MIN_STUCK_CPUS {
        use core::sync::atomic::Ordering;
        if FREEZE_NMI_FIRED
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            ext_cmos_write(CMOS_OFF_FREEZE_DETECTED, CMOS_MAGIC_FREEZE_DETECTED);
            CPU_WANT_NMI[cpu].store(1, Relaxed);
        }
    }
}

/// Called from the tail of `handle_vmexit` AFTER `reinject_idt_vectoring_event`
/// has run, so the write here isn't overwritten. Returns true iff this CPU
/// won the freeze-detector race above and must inject an NMI to guest on
/// the next vmentry.
#[inline]
pub fn preempt_timer_consume_nmi_request() -> bool {
    let cpu = super::host_idt::current_cpu_index();
    if cpu >= MAX_TRACKED_CPUS {
        return false;
    }
    CPU_WANT_NMI[cpu].swap(0, Relaxed) != 0
}

/// Diagnostic getter exposed via CTL id 130. Non-zero = detector fired since
/// last boot. Also readable persistently via Ext CMOS 0x2D.
pub fn freeze_nmi_fired() -> u64 {
    FREEZE_NMI_FIRED.load(Relaxed)
}

/// Diagnostic getter exposed via CTL id 131. Count of CPUs currently marked
/// as stuck at high IRQL with interrupts disabled.
pub fn freeze_stuck_cpu_count() -> u64 {
    let mut n = 0u64;
    for i in 0..MAX_TRACKED_CPUS {
        if CPU_STUCK_MARKED[i].load(Relaxed) != 0 {
            n += 1;
        }
    }
    n
}

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
        5 => {
            let b0 = cmos_read(0x72) as u64;
            let b1 = cmos_read(0x73) as u64;
            let b2 = cmos_read(0x74) as u64;
            let b3 = cmos_read(0x75) as u64;
            b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        }
        6 | 7 | 8 | 9 | 10 => cmos_read_step4(field),
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
    // Global interleaved ring (legacy).
    let idx = RING_IDX.fetch_add(1, Relaxed) as usize % RING_SIZE;
    RING_REASON[idx].store(exit_reason, Relaxed);
    RING_RIP[idx].store(guest_rip, Relaxed);
    RING_QUAL[idx].store(exit_qual, Relaxed);
    RING_RAX[idx].store(guest_rax, Relaxed);

    // Per-CPU ring keyed by rdtscp AUX.
    let cpu = rdtscp_aux() as usize % MAX_TRACKED_CPUS;
    let cpu_idx = PER_CPU_RING_IDX[cpu].fetch_add(1, Relaxed) as usize % PER_CPU_RING_SIZE;
    let slot = cpu * PER_CPU_RING_SIZE + cpu_idx;
    PER_CPU_RING_REASON[slot].store(exit_reason, Relaxed);
    PER_CPU_RING_RIP[slot].store(guest_rip, Relaxed);
    PER_CPU_RING_QUAL[slot].store(exit_qual, Relaxed);
    PER_CPU_RING_RAX[slot].store(guest_rax, Relaxed);
}

pub fn ring_entry(slot: u64, field: u64) -> u64 {
    let s = slot as usize;
    if s >= RING_SIZE {
        return u64::MAX;
    }
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

/// Read one field of one slot from a specific CPU's VM-exit ring.
///
/// `cpu` and `slot` are both 0-indexed; slots larger than `PER_CPU_RING_SIZE`
/// or CPUs larger than `MAX_TRACKED_CPUS` return `u64::MAX`. Slot ordering is
/// insertion order — the caller can pair with `per_cpu_ring_idx(cpu)` to
/// locate the newest entry.
pub fn per_cpu_ring_entry(cpu: u64, slot: u64, field: u64) -> u64 {
    let c = cpu as usize;
    let s = slot as usize;
    if c >= MAX_TRACKED_CPUS || s >= PER_CPU_RING_SIZE {
        return u64::MAX;
    }
    let idx = c * PER_CPU_RING_SIZE + s;
    match field {
        0 => PER_CPU_RING_REASON[idx].load(Relaxed),
        1 => PER_CPU_RING_RIP[idx].load(Relaxed),
        2 => PER_CPU_RING_QUAL[idx].load(Relaxed),
        3 => PER_CPU_RING_RAX[idx].load(Relaxed),
        _ => u64::MAX,
    }
}

/// Total number of writes seen by `cpu`'s ring; low bits (mod PER_CPU_RING_SIZE)
/// give the slot the NEXT write will land in, so `slot = (idx - 1) % SIZE` is
/// the newest completed entry.
pub fn per_cpu_ring_idx(cpu: u64) -> u64 {
    let c = cpu as usize;
    if c >= MAX_TRACKED_CPUS {
        return u64::MAX;
    }
    PER_CPU_RING_IDX[c].load(Relaxed)
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

#[inline]
fn rdtsc_now() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack),
        );
    }
    ((high as u64) << 32) | (low as u64)
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
        25 => super::host_idt::HOST_DEFAULT_COUNT.load(Relaxed),
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

    #[test]
    fn per_cpu_ring_records_and_returns_written_entry() {
        reset_per_cpu_ring_for_test();

        // Directly poke slot 0 of CPU 7 to avoid depending on rdtscp.
        let base = 7 * PER_CPU_RING_SIZE;
        PER_CPU_RING_REASON[base].store(0x1234_5678, Relaxed);
        PER_CPU_RING_RIP[base].store(0xdead_beef, Relaxed);
        PER_CPU_RING_QUAL[base].store(0x4141, Relaxed);
        PER_CPU_RING_RAX[base].store(0xcafe_babe, Relaxed);

        assert_eq!(per_cpu_ring_entry(7, 0, 0), 0x1234_5678);
        assert_eq!(per_cpu_ring_entry(7, 0, 1), 0xdead_beef);
        assert_eq!(per_cpu_ring_entry(7, 0, 2), 0x4141);
        assert_eq!(per_cpu_ring_entry(7, 0, 3), 0xcafe_babe);
        // Unrelated CPU/slot remains zero.
        assert_eq!(per_cpu_ring_entry(6, 0, 0), 0);
        assert_eq!(per_cpu_ring_entry(7, 1, 0), 0);
    }

    #[test]
    fn per_cpu_ring_rejects_out_of_range_indices() {
        assert_eq!(per_cpu_ring_entry(MAX_TRACKED_CPUS as u64, 0, 0), u64::MAX);
        assert_eq!(per_cpu_ring_entry(0, PER_CPU_RING_SIZE as u64, 0), u64::MAX);
        assert_eq!(per_cpu_ring_entry(0, 0, 42), u64::MAX);
        assert_eq!(per_cpu_ring_idx(MAX_TRACKED_CPUS as u64), u64::MAX);
    }

    #[test]
    fn observe_guest_rip_flags_calls_inside_watched_range() {
        let base = 0xFFFFF800_12340000;
        set_kebugcheckex_sentinel(base, 0xCCCC_DDDD_EEEE_FFFF);
        KEBUGCHECKEX_HITS.store(0, Relaxed);
        KEBUGCHECKEX_HIT_CPU.store(0, Relaxed);
        KEBUGCHECKEX_HIT_RIP.store(0, Relaxed);
        KEBUGCHECKEX_HIT_TSC.store(0, Relaxed);
        KEBUGCHECKEX_HIT_ARG0.store(0, Relaxed);

        // Below range — no hit.
        observe_guest_rip_for_bugcheck(base - 1, 0x139);
        assert_eq!(KEBUGCHECKEX_HITS.load(Relaxed), 0);

        // Inside prologue window — first hit captures context.
        observe_guest_rip_for_bugcheck(base + 4, 0x139);
        assert_eq!(KEBUGCHECKEX_HITS.load(Relaxed), 1);
        assert_eq!(KEBUGCHECKEX_HIT_RIP.load(Relaxed), base + 4);
        assert_eq!(KEBUGCHECKEX_HIT_ARG0.load(Relaxed), 0x139);
        let first_hit_rip = KEBUGCHECKEX_HIT_RIP.load(Relaxed);

        // Second hit increments counter but does not overwrite first context.
        observe_guest_rip_for_bugcheck(base + 20, 0x1AB);
        assert_eq!(KEBUGCHECKEX_HITS.load(Relaxed), 2);
        assert_eq!(KEBUGCHECKEX_HIT_RIP.load(Relaxed), first_hit_rip);

        // Just past window — no hit.
        observe_guest_rip_for_bugcheck(base + KEBUGCHECKEX_WATCH_LEN, 0);
        assert_eq!(KEBUGCHECKEX_HITS.load(Relaxed), 2);

        // Reset for other tests.
        KEBUGCHECKEX_ADDR.store(0, Relaxed);
        KEBUGCHECKEX_SENTINEL.store(0, Relaxed);
        KEBUGCHECKEX_HITS.store(0, Relaxed);
        KEBUGCHECKEX_HIT_CPU.store(0, Relaxed);
        KEBUGCHECKEX_HIT_RIP.store(0, Relaxed);
        KEBUGCHECKEX_HIT_TSC.store(0, Relaxed);
        KEBUGCHECKEX_HIT_ARG0.store(0, Relaxed);
    }

    #[test]
    fn observe_guest_rip_is_noop_before_sentinel_set() {
        KEBUGCHECKEX_ADDR.store(0, Relaxed);
        KEBUGCHECKEX_HITS.store(0, Relaxed);
        observe_guest_rip_for_bugcheck(0xdeadbeef, 0);
        assert_eq!(KEBUGCHECKEX_HITS.load(Relaxed), 0);
    }

    #[test]
    fn cmos_step4_field6_packs_state_bytes_lsb_first() {
        // The packing must place magic in the low byte and CPU/vector/hits
        // in successive bytes so a user-mode reader can unpack with shifts
        // that mirror the write layout above.
        let magic = 0xABu8;
        let hits = 3u8;
        let vector = 14u8;
        let cpu = 7u8;
        let total: u16 = 0x1234;

        let packed = (magic as u64)
            | ((hits as u64) << 8)
            | ((vector as u64) << 16)
            | ((cpu as u64) << 24)
            | (((total & 0xFF) as u64) << 32)
            | (((total >> 8) as u64) << 40);

        assert_eq!(packed & 0xFF, CMOS_MAGIC_STEP4 as u64);
        assert_eq!((packed >> 8) & 0xFF, hits as u64);
        assert_eq!((packed >> 16) & 0xFF, vector as u64);
        assert_eq!((packed >> 24) & 0xFF, cpu as u64);
        assert_eq!((packed >> 32) & 0xFFFF, total as u64);
    }

    #[test]
    fn cmos_step4_field7_bugcheck_arg0_roundtrips_as_u32() {
        let arg0: u32 = 0x0000_0139; // KERNEL_SECURITY_CHECK_FAILURE
        let packed = (arg0 as u64) & 0xFFFF_FFFF;
        assert_eq!(packed as u32, arg0);
    }

    #[test]
    fn cmos_read_step4_out_of_range_returns_sentinel() {
        assert_eq!(cmos_read_step4(0), u64::MAX);
        assert_eq!(cmos_read_step4(9), u64::MAX);
    }

    #[test]
    fn watchdog_field_reports_written_state_and_rejects_out_of_range() {
        HANDLER_MAX_DELTA[9].store(0xdeadbeef, Relaxed);
        HANDLER_MAX_DELTA_REASON[9].store(42, Relaxed);
        HANDLER_SLOW_COUNT[9].store(3, Relaxed);
        HANDLER_LAST_SLOW_REASON[9].store(48, Relaxed);
        HANDLER_LAST_SLOW_RIP[9].store(0x1122_3344, Relaxed);
        HANDLER_LAST_SLOW_DELTA[9].store(0x99, Relaxed);
        HANDLER_START_TSC[9].store(0xa5a5, Relaxed);
        HANDLER_LAST_EXIT_REASON[9].store(10, Relaxed);

        assert_eq!(watchdog_field(9, 0), 0xdeadbeef);
        assert_eq!(watchdog_field(9, 1), 42);
        assert_eq!(watchdog_field(9, 2), 3);
        assert_eq!(watchdog_field(9, 3), 48);
        assert_eq!(watchdog_field(9, 4), 0x1122_3344);
        assert_eq!(watchdog_field(9, 5), 0x99);
        assert_eq!(watchdog_field(9, 6), 0xa5a5);
        assert_eq!(watchdog_field(9, 7), 10);

        assert_eq!(watchdog_field(9, 42), u64::MAX);
        assert_eq!(watchdog_field(MAX_TRACKED_CPUS as u64, 0), u64::MAX);

        // Reset so cross-test contamination does not leak.
        HANDLER_MAX_DELTA[9].store(0, Relaxed);
        HANDLER_MAX_DELTA_REASON[9].store(0, Relaxed);
        HANDLER_SLOW_COUNT[9].store(0, Relaxed);
        HANDLER_LAST_SLOW_REASON[9].store(0, Relaxed);
        HANDLER_LAST_SLOW_RIP[9].store(0, Relaxed);
        HANDLER_LAST_SLOW_DELTA[9].store(0, Relaxed);
        HANDLER_START_TSC[9].store(0, Relaxed);
        HANDLER_LAST_EXIT_REASON[9].store(0, Relaxed);
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
        30 => super::host_idt::HOST_FAULT_TOTAL.load(Relaxed),
        31 => super::host_idt::HOST_FIRST_FAULT_VECTOR.load(Relaxed),
        32 => super::host_idt::HOST_FIRST_FAULT_RIP.load(Relaxed),
        33 => super::host_idt::HOST_FIRST_FAULT_RSP.load(Relaxed),
        34 => super::host_idt::HOST_FIRST_FAULT_ERR.load(Relaxed),
        35 => super::host_idt::HOST_FIRST_FAULT_CPU.load(Relaxed),
        36 => super::host_idt::NMI_FAULT_RIP.load(Relaxed),
        37 => super::host_idt::NMI_FAULT_RSP.load(Relaxed),
        38 => super::host_idt::GP_FAULT_RSP.load(Relaxed),
        39 => super::host_idt::GP_FAULT_ERR.load(Relaxed),
        40 => super::host_idt::PF_FAULT_RSP.load(Relaxed),
        41 => super::host_idt::PF_FAULT_ERR.load(Relaxed),
        42 => super::host_idt::MC_FAULT_RSP.load(Relaxed),
        43 => super::host_idt::HOST_DF_COUNT.load(Relaxed),
        44 => super::host_idt::DF_FAULT_RIP.load(Relaxed),
        45 => super::host_idt::DF_FAULT_RSP.load(Relaxed),
        46 => super::host_idt::HOST_DEFAULT_RIP.load(Relaxed),
        47 => super::host_idt::HOST_DEFAULT_RSP.load(Relaxed),
        48 => PER_CPU_RING_SIZE as u64,
        49 => MAX_TRACKED_CPUS as u64,
        50 => KEBUGCHECKEX_ADDR.load(Relaxed),
        51 => KEBUGCHECKEX_SENTINEL.load(Relaxed),
        52 => KEBUGCHECKEX_HITS.load(Relaxed),
        53 => KEBUGCHECKEX_HIT_CPU.load(Relaxed),
        54 => KEBUGCHECKEX_HIT_RIP.load(Relaxed),
        55 => KEBUGCHECKEX_HIT_TSC.load(Relaxed),
        56 => KEBUGCHECKEX_HIT_ARG0.load(Relaxed),
        57 => EFER_READ_COUNT.load(Relaxed),
        58 => EFER_WRITE_COUNT.load(Relaxed),
        59 => APERF_READ_COUNT.load(Relaxed),
        60 => MPERF_READ_COUNT.load(Relaxed),
        61 => DEBUGCTL_READ_COUNT.load(Relaxed),
        62 => DEBUGCTL_WRITE_COUNT.load(Relaxed),
        63 => LBR_STACK_READ_COUNT.load(Relaxed),
        64 => LBR_DEBUGCTL_SHADOW.load(Relaxed),
        65 => BUGCHECK_CALLBACK_FIRED.load(Relaxed),
        66 => super::host_idt::HOST_DEFAULT_SOFT_COUNT.load(Relaxed),
        67 => super::host_idt::HOST_DEFAULT_SOFT_RIP.load(Relaxed),
        68 => LBR_SAVE_COUNT.load(Relaxed),
        69 => LBR_RESTORE_COUNT.load(Relaxed),
        70 => super::bugcheck_hook::HOOK_PAGE_PA.load(Relaxed),
        71 => super::bugcheck_hook::HOOK_FN_START_VA.load(Relaxed),
        72 => super::bugcheck_hook::HOOK_FIRED_TSC.load(Relaxed),
        73 => super::bugcheck_hook::HOOK_FIRED_RIP.load(Relaxed),
        74 => super::bugcheck_hook::HOOK_FIRED_CPU.load(Relaxed),
        75 => super::bugcheck_hook::HOOK_SPURIOUS_COUNT.load(Relaxed),
        76 => BUGCHECK_ENTRY_HOOK_FIRED.load(Relaxed),
        80 => super::vmexit::idle::MWAIT_EXITS.load(Relaxed),
        81 => super::vmexit::idle::MWAIT_CLAMPED.load(Relaxed),
        82 => super::vmexit::idle::MONITOR_EXITS.load(Relaxed),
        83 => super::vmexit::idle::MWAIT_MAX_REQUESTED_CSTATE.load(Relaxed),
        // Hardware MSR_PKG_CST_CONFIG_CONTROL raw read — bypasses the
        // guest-facing shadow so we can tell whether BIOS actually set
        // Package C State Limit or the shadow is doing all the work.
        // bits[2:0]: 000=no limit, 001=C1, 010=C2, 011=C3, 110=C6, 111=C7/C8.
        84 => unsafe { x86::msr::rdmsr(0xE2) },
        85 => super::vmexit::idle::HLT_EXITS.load(Relaxed),
        // CMOS retention experiment (Phase 0, 2026-07-12).
        90 => CMOS_RET_PREV_MAGIC.load(Relaxed),
        91 => CMOS_RET_PREV_COUNTER.load(Relaxed),
        92 => CMOS_RET_PREV_LAST_SESSION.load(Relaxed),
        93 => CMOS_RET_PREV_THIS_SESSION.load(Relaxed),
        94 => CMOS_RET_PREV_COMPLETION.load(Relaxed),
        95 => CMOS_RET_PREV_CHECKSUM_OK.load(Relaxed),
        96 => CMOS_RET_NEW_COUNTER.load(Relaxed),
        97 => CMOS_RET_NEW_THIS_SESSION.load(Relaxed),
        98 => CMOS_RET_EXPERIMENT_RAN.load(Relaxed),
        // Port 0x80 breadcrumb (2026-07-15).
        100 => PORT80_LAST.load(Relaxed) as u64,
        101 => PORT80_WRITE_COUNT.load(Relaxed),
        // Layer 4 HV vs Guest classifier (2026-07-15).
        102 => handler_active_bitmap_lo(),
        103 => handler_active_count(),
        // Layer 3 CMOS mirror readout (2026-07-15). CTL 110 refreshes the
        // cache from CMOS (~30 reads), CTL 111-116 read that cache.
        // cpuid_ping must call CTL 110 first, then the others.
        110 => layer3_refresh_cache() as u64,      // slot_id (0=none, 1=A, 2=B) + refresh
        111 => LAYER3_CACHE_SEQ.load(Relaxed),
        112 => LAYER3_CACHE_PORT80.load(Relaxed) as u64,
        113 => LAYER3_CACHE_BITMAP.load(Relaxed),
        114 => LAYER3_CACHE_LAST_EXIT.load(Relaxed) as u64,
        115 => LAYER3_CACHE_COUNT.load(Relaxed) as u64,
        116 => LAYER3_CACHE_VALID.load(Relaxed) as u64,
        117 => LAYER3_FLUSH_COUNT.load(Relaxed),   // total vmexits (not flushes)
        120 => LAYER3_SEQUENCE.load(Relaxed),      // actual flushes done — used by cpuid_ping origin judgment
        // Smart freeze detector diagnostics (2026-07-16). Non-zero fired
        // means the detector triggered NMI-inject-BSOD path since HV load;
        // stuck_cpus is a live snapshot of how many CPUs are currently
        // marked as stuck at high IRQL with IF=0.
        130 => freeze_nmi_fired(),
        131 => freeze_stuck_cpu_count(),
        // Persistent (CMOS-mirrored) freeze detector state. Survives across
        // the RST/BSOD reboot so post-mortem cpuid_ping can see whether the
        // last boot's detector fired (132) and how close it came (133+134).
        132 => ext_cmos_read(CMOS_OFF_FREEZE_DETECTED) as u64,
        133 => FREEZE_MAX_STUCK_SEEN.load(Relaxed),
        134 => ext_cmos_read(CMOS_OFF_FREEZE_PEAK) as u64,
        // Tick counter — verifies detector is armed. When tick counter is
        // very low (<40), detector hasn't armed yet and freeze data would
        // be missed.
        135 => FREEZE_TICK_COUNTER.load(Relaxed),
        // Layer 6 persistent per-CPU snapshot (2026-07-16).
        // 140 — valid flag: 1 if we captured PREV BOOT CMOS at driver_entry.
        // 141 — PREV BOOT global sequence at freeze time (16-bit).
        // 142+cpu (142..165, cpu 0..23) — PREV BOOT per-CPU seq low byte.
        //   Gap between (141 & 0xFF) and this = "how far behind this CPU
        //   was at snapshot" = how long it went without vmexits. Large gap
        //   → CPU stuck earlier.
        // 166+cpu (166..189, cpu 0..23) — PREV BOOT per-CPU last exit reason.
        //   Which handler this CPU last vmexited into before stopping.
        // 190 — SNAP_GLOBAL_SEQ (this boot, live).
        // 191+cpu (191..214) — SNAP_CPU_LAST_FLUSH_SEQ (this boot, live).
        // 215+cpu (215..238) — SNAP_CPU_LAST_REASON (this boot, live).
        140 => SNAP_PREV_VALID.load(Relaxed),
        141 => SNAP_PREV_GLOBAL_SEQ.load(Relaxed),
        142..=165 => {
            let cpu = (id - 142) as usize;
            SNAP_PREV_CPU_SEQ[cpu].load(Relaxed)
        }
        166..=189 => {
            let cpu = (id - 166) as usize;
            SNAP_PREV_CPU_REASON[cpu].load(Relaxed)
        }
        190 => SNAP_GLOBAL_SEQ.load(Relaxed),
        191..=214 => {
            let cpu = (id - 191) as usize;
            SNAP_CPU_LAST_FLUSH_SEQ[cpu].load(Relaxed)
        }
        215..=238 => {
            let cpu = (id - 215) as usize;
            SNAP_CPU_LAST_REASON[cpu].load(Relaxed)
        }
        // Rare-exit RING CTL block (2026-07-16 replaces single-slot 240-249).
        // 240 — PREV BOOT ring magic valid (1 = ring present from prev boot).
        // 241 — PREV BOOT ring head (next-write index, so newest slot =
        //       (head - 1) mod RARE_RING_SLOTS).
        // 242 — PREV BOOT ring count (saturating u8, total rare exits seen).
        // 243..=258 — PREV slot i (0..=3) fields (cpu, reason, rip, seq_lo):
        //   ID = 243 + slot*4 + field
        //     field 0 = CPU, 1 = reason, 2 = RIP low 32, 3 = global seq low 8.
        // 259 — THIS BOOT total rare-exit count (RAM, monotonic).
        240 => RARE_RING_PREV_MAGIC_OK.load(Relaxed),
        241 => RARE_RING_PREV_HEAD.load(Relaxed),
        242 => RARE_RING_PREV_COUNT.load(Relaxed),
        243..=258 => {
            let idx = (id - 243) as usize;
            let slot = idx / 4;
            let field = idx % 4;
            match field {
                0 => RARE_RING_PREV_CPU[slot].load(Relaxed),
                1 => RARE_RING_PREV_REASON[slot].load(Relaxed),
                2 => RARE_RING_PREV_RIP[slot].load(Relaxed),
                3 => RARE_RING_PREV_SEQ_LO[slot].load(Relaxed),
                _ => 0,
            }
        }
        259 => RARE_TOTAL_COUNT.load(Relaxed),
        // Live Ext CMOS byte readback (debug — for verifying writes land).
        // 260..=275 = read Ext CMOS 0x00 + (id-260), one byte each (16 bytes,
        // full ring region 0x00-0x0F).
        260..=275 => ext_cmos_read(RARE_RING_MAGIC_OFF + (id - 260) as u8) as u64,
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

#[cfg(test)]
pub fn reset_per_cpu_ring_for_test() {
    for slot in 0..PER_CPU_RING_LEN {
        PER_CPU_RING_REASON[slot].store(0, Relaxed);
        PER_CPU_RING_RIP[slot].store(0, Relaxed);
        PER_CPU_RING_QUAL[slot].store(0, Relaxed);
        PER_CPU_RING_RAX[slot].store(0, Relaxed);
    }
    for cpu in 0..MAX_TRACKED_CPUS {
        PER_CPU_RING_IDX[cpu].store(0, Relaxed);
    }
}
