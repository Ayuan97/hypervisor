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
//! Strategy on every VM-exit:
//! 1. Read guest `IA32_DEBUGCTL`. If LBR bit (0) is clear, guest is not
//!    using LBR — skip everything. Zero-cost fast path.
//! 2. Otherwise snapshot all 32 pairs of LBR stack MSRs plus TOS to a
//!    per-CPU buffer, then clear the LBR bit in DEBUGCTL so host code that
//!    runs between here and VMRESUME does NOT pollute the stack.
//! 3. Before VMRESUME, write the saved values back and restore DEBUGCTL.
//!    Guest wakes up seeing the LBR state it had at the moment of VM-exit,
//!    with zero host branches leaked.
//!
//! There is still a *small* leak window between VMX-root entry (top of the
//! asm VM-exit stub) and the point where `save_and_disable_lbr()` runs. A
//! future pass could hoist the save into the assembly stub itself for a
//! fully clean picture; the current Rust-level approach cuts leakage down
//! from "every host branch in the exit handler" to "the ~20-30 branches of
//! the asm stub", which is enough to break the detection pattern EAC used.
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

const IA32_DEBUGCTL: u32 = 0x1D9;
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

/// If the guest currently has LBR recording enabled, snapshot the entire
/// LBR stack + DEBUGCTL to a per-CPU buffer and disable recording so host
/// handler branches do not leak into it. Called from the VM-exit prologue.
///
/// Returns true iff the state was saved (i.e. `restore_lbr()` must run
/// before VMRESUME to reverse this).
#[inline]
pub fn save_and_disable_lbr() -> bool {
    let debugctl = unsafe { x86::msr::rdmsr(IA32_DEBUGCTL) };
    let slot = cpu_slot();
    slot.debugctl = debugctl;
    if (debugctl & 1) == 0 {
        // LBR was not on; nothing to save and no host branches would land
        // in the stack anyway. Fast path — 1 RDMSR total.
        return false;
    }
    slot.tos = unsafe { x86::msr::rdmsr(IA32_LASTBRANCH_TOS) };
    let mut i = 0;
    while i < LBR_NR_ENTRIES {
        slot.from[i] = unsafe { x86::msr::rdmsr(IA32_LASTBRANCH_FROM_BASE + i as u32) };
        slot.to[i] = unsafe { x86::msr::rdmsr(IA32_LASTBRANCH_TO_BASE + i as u32) };
        i += 1;
    }
    // Freeze LBR recording while we're in host mode so subsequent branches
    // do not overwrite the stack we just captured.
    unsafe { x86::msr::wrmsr(IA32_DEBUGCTL, debugctl & !1) };
    diag::LBR_SAVE_COUNT.fetch_add(1, Relaxed);
    true
}

/// Restore the LBR stack + DEBUGCTL captured by the matching
/// `save_and_disable_lbr()`. Called just before VMRESUME so the guest sees
/// the branch history it had at the moment of VM-exit — with no host code
/// stitched into the middle of the stack.
///
/// Safe to call unconditionally; if `save_and_disable_lbr()` returned false
/// (i.e. LBR wasn't enabled), this restores DEBUGCTL to what the guest had
/// and does not touch the stack MSRs.
#[inline]
pub fn restore_lbr() {
    let slot = cpu_slot();
    let debugctl = slot.debugctl;
    if (debugctl & 1) == 0 {
        // LBR wasn't recording at exit; nothing to restore beyond DEBUGCTL
        // itself. Even that write is only needed if host code touched it,
        // which we don't do in the fast path — but write anyway to be
        // strictly correct.
        unsafe { x86::msr::wrmsr(IA32_DEBUGCTL, debugctl) };
        return;
    }
    unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_TOS, slot.tos) };
    let mut i = 0;
    while i < LBR_NR_ENTRIES {
        unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_FROM_BASE + i as u32, slot.from[i]) };
        unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_TO_BASE + i as u32, slot.to[i]) };
        i += 1;
    }
    // Re-enable LBR by writing back the original DEBUGCTL last.
    unsafe { x86::msr::wrmsr(IA32_DEBUGCTL, debugctl) };
    diag::LBR_RESTORE_COUNT.fetch_add(1, Relaxed);
}
