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
//! The raw legacy-MSR shadow is disabled by default and requires the explicit
//! build flag `HV_LBR_SHADOW=1`. Hybrid processors can expose different LBR
//! capabilities on different core types, and an unsupported RDMSR/WRMSR in
//! VMX root cannot be recovered like a guest #GP. When explicitly enabled:
//! 1. Read guest `IA32_DEBUGCTL` from the VMCS. If LBR bit (0) is clear, skip.
//! 2. Snapshot all 32 pairs of LBR stack MSRs plus TOS to a per-CPU buffer.
//!    VM-exit already clears host `IA32_DEBUGCTL`, so host handler branches do
//!    not need an additional hardware write here.
//! 3. Before VMRESUME, write the saved values back. Guest sees the LBR state
//!    it had at the moment of VM-exit, with no handler branches in the stack.
//!
//! There is still a *small* leak window between VMX-root entry (top of the
//! asm VM-exit stub) and the point where `save_and_disable_lbr()` runs. A
//! future pass could hoist the save into the assembly stub itself for a
//! fully clean picture; the current Rust-level approach cuts leakage down
//! from "every host branch in the exit handler" to "the ~20-30 branches of
//! the asm stub", which is enough to break the detection pattern EAC used.
//!
//! Cost: 65 RDMSR + 65 WRMSR per VM-exit (~6600 cycles), only when the guest
//! LBR bit is enabled. Windows normally leaves LBR off.

use {
    crate::intel::{diag, host_idt, support::vmread_checked},
    core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicU8, Ordering::Relaxed},
    },
    x86::{cpuid::cpuid, vmx::vmcs::guest as vmcs_guest},
};

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
const LBR_CAPABILITY_UNKNOWN: u8 = 0;
const LBR_CAPABILITY_SUPPORTED: u8 = 1;
const LBR_CAPABILITY_UNSUPPORTED: u8 = 2;
/// Match `diag::MAX_TRACKED_CPUS`. Kept as a separate const so this module
/// does not depend on `diag`'s public re-export.
const MAX_LBR_CPUS: usize = 64;
static LBR_32_CAPABILITY: [AtomicU8; MAX_LBR_CPUS] =
    [const { AtomicU8::new(LBR_CAPABILITY_UNKNOWN) }; MAX_LBR_CPUS];

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
fn cpu_slot() -> Option<&'static mut LbrSlot> {
    let cpu = host_idt::current_cpu_index();
    (cpu < MAX_LBR_CPUS).then(|| unsafe { &mut *SLOTS.0[cpu].get() })
}

fn depth_mask_supports_32(mask: u32) -> bool {
    // CPUID.1C:EAX[n] advertises support for an architectural LBR depth of
    // 8*(n+1). Bit 3 therefore means a 32-entry stack is available.
    mask & (1 << 3) != 0
}

const fn lbr_shadow_enabled(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 1 && bytes[0] == b'1'
}

fn host_lbr_32_supported() -> bool {
    let cpu = host_idt::current_cpu_index();
    if cpu >= MAX_LBR_CPUS {
        return false;
    }
    let capability = &LBR_32_CAPABILITY[cpu];
    match capability.load(Relaxed) {
        LBR_CAPABILITY_SUPPORTED => return true,
        LBR_CAPABILITY_UNSUPPORTED => return false,
        _ => {}
    }

    let max_basic = cpuid!(0, 0).eax;
    let supported = max_basic >= 0x1C && depth_mask_supports_32(cpuid!(0x1C, 0).eax);
    let state = if supported {
        LBR_CAPABILITY_SUPPORTED
    } else {
        LBR_CAPABILITY_UNSUPPORTED
    };
    let _ = capability.compare_exchange(
        LBR_CAPABILITY_UNKNOWN,
        state,
        core::sync::atomic::Ordering::Release,
        Relaxed,
    );
    supported
}

/// If the guest currently has LBR recording enabled, snapshot the entire LBR
/// stack to a per-CPU buffer. VM-exit has already
/// cleared host DEBUGCTL, so handler branches do not leak into it.
///
/// Returns true iff the state was saved (i.e. `restore_lbr()` must run
/// before VMRESUME to reverse this).
#[inline]
pub fn save_and_disable_lbr() -> bool {
    if !lbr_shadow_enabled(option_env!("HV_LBR_SHADOW")) {
        return false;
    }

    // VM-exit clears host IA32_DEBUGCTL. Read the guest value from the VMCS
    // so we only snapshot when guest LBR recording was actually enabled.
    let debugctl = vmread_checked(vmcs_guest::IA32_DEBUGCTL_FULL).unwrap_or(0);
    let Some(slot) = cpu_slot() else {
        return false;
    };
    slot.debugctl = debugctl;
    if (debugctl & 1) == 0 {
        return false;
    }
    // Never probe unimplemented LASTBRANCH_* MSRs. On CPUs without the
    // advertised 32-entry architectural depth, leave the guest's native
    // LBR state alone; VM-exit already cleared DEBUGCTL while root code runs.
    if !host_lbr_32_supported() {
        slot.debugctl = 0;
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
    let Some(slot) = cpu_slot() else {
        return;
    };
    if (slot.debugctl & 1) == 0 {
        // Guest didn't have LBR on at exit — nothing to restore. DEBUGCTL
        // is auto-restored by VM-entry via LOAD_DEBUG_CONTROLS = 1 from
        // GUEST_IA32_DEBUGCTL_FULL, so we don't touch it either.
        return;
    }
    // Rewrite the LBR stack MSRs back to the guest snapshot. VM-entry
    // will re-arm DEBUGCTL bit 0 for us via the LOAD_DEBUG_CONTROLS
    // control, resuming recording from the very address the guest was
    // about to execute.
    unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_TOS, slot.tos) };
    let mut i = 0;
    while i < LBR_NR_ENTRIES {
        unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_FROM_BASE + i as u32, slot.from[i]) };
        unsafe { x86::msr::wrmsr(IA32_LASTBRANCH_TO_BASE + i as u32, slot.to[i]) };
        i += 1;
    }
    diag::LBR_RESTORE_COUNT.fetch_add(1, Relaxed);
    // Make recovery idempotent.  The VM-exit error path may call this after a
    // normal handler already restored the guest snapshot.
    slot.debugctl = 0;
}

#[cfg(test)]
mod tests {
    use super::{depth_mask_supports_32, lbr_shadow_enabled};

    #[test]
    fn architectural_lbr_depth_mask_requires_32_entry_bit() {
        assert!(!depth_mask_supports_32(0));
        assert!(!depth_mask_supports_32(1 << 2));
        assert!(depth_mask_supports_32(1 << 3));
    }

    #[test]
    fn raw_lbr_shadow_requires_explicit_build_opt_in() {
        assert!(!lbr_shadow_enabled(None));
        assert!(!lbr_shadow_enabled(Some("0")));
        assert!(!lbr_shadow_enabled(Some("true")));
        assert!(lbr_shadow_enabled(Some("1")));
    }
}
