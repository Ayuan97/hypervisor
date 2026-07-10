//! LBR (Last Branch Record) save/restore for VM-exit stealth.
//!
//! Without this, every VM-exit runs host handler code whose branches get
//! recorded into the LBR stack. When the guest reads the LBR MSRs (e.g. EAC
//! doing an LBR-based detection round), it sees `LASTBRANCH_TO_i` values
//! pointing at HV code — a strong hypervisor signature.
//!
//! The 2026-07-09 EAC session confirmed this is a live detection path:
//! DEBUGCTL was written 206 times, LBR stack read 895K+ times, and the
//! session eventually froze even though the P1 CPUID/MSR consistency was
//! clean.
//!
//! Strategy on every VM-exit (P3.5 asm-freeze + Rust stack save layout):
//! 1. `vmexit_stub` in vmlaunch.rs samples DEBUGCTL and unconditionally
//!    clears bit 0 (LBR) BEFORE any conditional/call runs, then stashes the
//!    original DEBUGCTL into `GuestRegisters::saved_debugctl`.
//! 2. Rust's `save_and_disable_lbr(guest_debugctl)` reads that stashed
//!    value. If bit 0 was clear, guest was not recording — nothing to save.
//!    Otherwise snapshot all 32 pairs of LBR stack MSRs plus TOS to a
//!    per-CPU buffer. Hardware is already frozen so no host branch will
//!    overwrite the snapshot between here and VMRESUME.
//! 3. Before VMRESUME the mirror `restore_lbr()` writes the stack MSRs
//!    back if we saved. `vmexit_restore` in vmlaunch.rs then rewrites
//!    hardware DEBUGCTL with the stashed guest value, re-arming LBR
//!    if the guest had it on.
//!
//! Leak window before P3.5: ~20-30 host branches from Rust prologue to
//! save call would land in the LBR stack. After P3.5: zero host branches
//! reach LBR — asm freezes hardware in straight-line code before any
//! branch executes, and Rust never touches DEBUGCTL bit 0 again.
//!
//! Cost: 66 RDMSR + 66 WRMSR per VM-exit (~6600 cycles). Only paid when
//! the guest actually has LBR enabled — Windows kernel does not turn it on
//! by default, so normal ops see no overhead. When EAC enables it, we
//! trade ~6% CPU for stealth on that specific detection path.

use {
    crate::intel::diag,
    core::{
        cell::UnsafeCell,
        sync::atomic::Ordering::Relaxed,
    },
};

// IA32_DEBUGCTL (0x1D9) is no longer touched from Rust — vmexit_stub /
// vmexit_restore own the freeze+restore. Left as a comment marker so
// grep(1) can still find the ownership handoff.
const IA32_LASTBRANCH_TOS: u32 = 0x1C9;
const IA32_LASTBRANCH_FROM_BASE: u32 = 0x680;
/// LASTBRANCH_TO_i lives at `0x6C0 + i` on Nehalem-and-later (Intel SDM Vol 4).
/// An earlier version of this file mistakenly used `0x6A0`, which is the
/// LASTBRANCH_INFO_i / reserved region — so P3.1 save/restore silently
/// missed the actual TO stack and host branches still leaked to the guest.
const IA32_LASTBRANCH_TO_BASE: u32 = 0x6C0;

/// Number of LBR entries on Raptor Lake / Alder Lake — the target CPU. Older
/// (< Skylake) or newer CPUs may support fewer or more, but 32 is the safe
/// upper bound for the platform we ship on; extra WRMSRs to unimplemented
/// slots on smaller CPUs will fault via #GP, which we accept as a deployment
/// error (log via BLR_CPUID_MISMATCH counter and fall back).
const LBR_NR_ENTRIES: usize = 32;

/// Match `diag::MAX_TRACKED_CPUS`. Kept as a separate const so this module
/// does not depend on `diag`'s public re-export.
const MAX_LBR_CPUS: usize = 64;

#[repr(C, align(64))]
struct LbrSlot {
    /// Guest's DEBUGCTL at the moment of VM-exit. Bit 0 tracks whether LBR
    /// was enabled — we use it as the "did we actually save?" flag.
    debugctl: u64,
    /// Saved LBR top-of-stack pointer.
    tos: u64,
    /// Saved `LASTBRANCH_FROM_i` values (source RIPs).
    from: [u64; LBR_NR_ENTRIES],
    /// Saved `LASTBRANCH_TO_i` values (destination RIPs).
    to: [u64; LBR_NR_ENTRIES],
}

impl LbrSlot {
    const fn zero() -> Self {
        Self {
            debugctl: 0,
            tos: 0,
            from: [0; LBR_NR_ENTRIES],
            to: [0; LBR_NR_ENTRIES],
        }
    }
}

/// Per-CPU save slots. Accessed via CPU index only (no cross-CPU sharing),
/// so a raw `UnsafeCell` array is safe.
#[repr(transparent)]
struct SlotArray([UnsafeCell<LbrSlot>; MAX_LBR_CPUS]);
unsafe impl Sync for SlotArray {}

const EMPTY_SLOT: UnsafeCell<LbrSlot> = UnsafeCell::new(LbrSlot::zero());
static SLOTS: SlotArray = SlotArray([EMPTY_SLOT; MAX_LBR_CPUS]);

#[inline]
fn cpu_index() -> usize {
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
    (aux as usize) & (MAX_LBR_CPUS - 1)
}

#[inline]
fn cpu_slot() -> &'static mut LbrSlot {
    unsafe { &mut *SLOTS.0[cpu_index()].get() }
}

/// Snapshot the LBR stack to a per-CPU buffer if the guest had LBR
/// recording on. Called from the VM-exit prologue after the asm stub has
/// already frozen hardware DEBUGCTL bit 0 and stashed the original guest
/// value in `GuestRegisters::saved_debugctl`.
///
/// `guest_debugctl` is that stashed original — bit 0 tells us whether the
/// guest had LBR enabled (i.e. whether the current stack contents belong
/// to the guest and must be preserved across the VM-exit round-trip).
///
/// Returns true iff the stack was saved (i.e. `restore_lbr()` must run
/// before VMRESUME to reverse this).
#[inline]
pub fn save_and_disable_lbr(guest_debugctl: u64) -> bool {
    // NB: hardware DEBUGCTL bit 0 is already 0 at this point (asm cleared
    // it). We do NOT touch DEBUGCTL from Rust anymore — vmexit_restore
    // rewrites the stashed original just before VMRESUME.
    let slot = cpu_slot();
    slot.debugctl = guest_debugctl;
    if (guest_debugctl & 1) == 0 {
        // LBR was not on for the guest; stack contents are stale garbage
        // from prior state, not worth saving. Fast path — zero MSRs.
        return false;
    }
    slot.tos = unsafe { x86::msr::rdmsr(IA32_LASTBRANCH_TOS) };
    let mut i = 0;
    while i < LBR_NR_ENTRIES {
        slot.from[i] = unsafe { x86::msr::rdmsr(IA32_LASTBRANCH_FROM_BASE + i as u32) };
        slot.to[i] = unsafe { x86::msr::rdmsr(IA32_LASTBRANCH_TO_BASE + i as u32) };
        i += 1;
    }
    diag::LBR_SAVE_COUNT.fetch_add(1, Relaxed);
    true
}

/// Restore the LBR stack captured by the matching `save_and_disable_lbr()`.
/// Called just before VMRESUME so the guest sees the branch history it had
/// at the moment of VM-exit — with no host code stitched into it.
///
/// Safe to call unconditionally; if `save_and_disable_lbr()` returned false
/// (i.e. LBR wasn't enabled), this is a no-op — vmexit_restore's WRMSR to
/// DEBUGCTL is what re-arms LBR on the guest side.
#[inline]
pub fn restore_lbr() {
    let slot = cpu_slot();
    let debugctl = slot.debugctl;
    if (debugctl & 1) == 0 {
        // Guest didn't have LBR on; nothing in the stack belongs to it.
        // vmexit_restore will still WRMSR the original DEBUGCTL for us so
        // guest state is coherent — we just don't touch stack MSRs.
        return;
    }
    unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_TOS, slot.tos) };
    let mut i = 0;
    while i < LBR_NR_ENTRIES {
        unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_FROM_BASE + i as u32, slot.from[i]) };
        unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_TO_BASE + i as u32, slot.to[i]) };
        i += 1;
    }
    diag::LBR_RESTORE_COUNT.fetch_add(1, Relaxed);
}
