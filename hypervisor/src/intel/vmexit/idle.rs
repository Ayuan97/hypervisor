//! MWAIT / MONITOR interception — clamp guest package C-state hints to C1.
//!
//! Intel Raptor Lake spec update 740518 documents:
//!   - RPL038: package C6/C8 exit → PCU MCE (MCACOD=0402h, MSCOD=0409h /
//!     0441h / 0462h). "No Fix."
//!   - RPL044: package C6 entry → MCE MCACOD=0402h, MSCOD=0485h/046Ch.
//!     "No Fix."
//!
//! Under this HV a Rust + EAC workload reproduces WHEA fatal-error records
//! attributed to PMC (Power Management Controller) events, matching the
//! errata's signature. Fix: never let the CPU transition into a package
//! C-state deeper than C1. Two complementary paths achieve this:
//!
//!   1. Trap MWAIT and rewrite the guest's C-state hint (EAX bits [7:4])
//!      to zero (C1) when it asks for C6/C7/C8, then execute HLT in host
//!      as the C1-equivalent wait.
//!   2. Trap MONITOR — MWAIT semantics require the paired MONITOR to arm
//!      an address, but our HLT-based emulation ignores the address, so we
//!      just advance past the MONITOR.
//!
//! Guest sees MWAIT return on any host-visible interrupt (timer, IPI,
//! device). Windows kernel's idle loop naturally handles a short/spurious
//! MWAIT return by re-evaluating scheduling; no wake edge is lost, because
//! external interrupts still route to the guest via the normal pin-based
//! control path (external-interrupt-exiting=0).
//!
//! The clamp is bypassed by `minimal_mode()` or `HV_NO_CSTATE_CLAMP=1` at
//! build time, so the effect can be A/B tested without a code revert.

use {
    crate::{
        intel::{diag, vmexit::ExitType, vmx::Vmx},
        utils::capture::GuestRegisters,
    },
    core::sync::atomic::{AtomicU64, Ordering::Relaxed},
};

/// Number of MWAIT VM-exits handled. Exposed via CTL id 80.
pub static MWAIT_EXITS: AtomicU64 = AtomicU64::new(0);

/// Number of MWAITs whose C-state hint was clamped down from >=C2 to C1.
/// Exposed via CTL id 81.
pub static MWAIT_CLAMPED: AtomicU64 = AtomicU64::new(0);

/// Number of MONITOR VM-exits skipped. Exposed via CTL id 82.
pub static MONITOR_EXITS: AtomicU64 = AtomicU64::new(0);

/// Highest deep C-state hint the guest ever asked for (bits [7:4] of MWAIT
/// EAX). Useful for confirming Windows really was trying to enter C6+.
/// Exposed via CTL id 83.
pub static MWAIT_MAX_REQUESTED_CSTATE: AtomicU64 = AtomicU64::new(0);

/// MWAIT VM-exit handler. Called from `handle_vmexit` when basic exit
/// reason == 36 (MWAIT). The guest's chosen C-state hint sits in EAX (Intel
/// SDM Vol 2A Table 4-30):
///   EAX[7:4] = target C-state
///     0 → C0 (do not sleep)
///     1 → C1
///     2 → C2
///     3 → C3
///     ...
///     6 → C6
///     7 → C7/C7s
///     8 → C8
///
/// We clamp any request for C2+ down to C1 and satisfy the wait with a
/// host-side `hlt`. C0/C1 requests execute the equivalent host `hlt` too —
/// splitting the fast paths adds complexity without any measurable win.
#[inline]
pub fn handle_mwait(guest_registers: &mut GuestRegisters, _vmx: &mut Vmx) -> ExitType {
    MWAIT_EXITS.fetch_add(1, Relaxed);

    let eax = (guest_registers.rax & 0xFFFF_FFFF) as u32;
    let requested_cstate = ((eax >> 4) & 0xF) as u64;

    // Track the deepest sleep the guest ever asked for — one atomic max
    // via CAS-loop is cheap and gives us clear evidence in cpuid_ping
    // that Windows really was targeting C6+ before the clamp.
    let mut cur = MWAIT_MAX_REQUESTED_CSTATE.load(Relaxed);
    while requested_cstate > cur {
        match MWAIT_MAX_REQUESTED_CSTATE.compare_exchange(
            cur,
            requested_cstate,
            Relaxed,
            Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }

    if requested_cstate >= 2 {
        MWAIT_CLAMPED.fetch_add(1, Relaxed);
    }

    diag::cpu_enter_phase(diag::PHASE_PRE_VMRESUME);

    // Host-side wait: sti + hlt + cli. This puts the physical core into
    // C1 (or C0 if any interrupt is already pending) and returns as soon
    // as any host-visible interrupt fires. We never enter package C6/C8
    // because we never issue MWAIT with those hints, and MSR 0xE2 is
    // shadowed to advertise the same clamp back to the guest OS.
    unsafe {
        core::arch::asm!(
            "sti",
            "hlt",
            "cli",
            options(nomem, nostack),
        );
    }

    ExitType::IncrementRIP
}

/// MONITOR VM-exit handler. Called from `handle_vmexit` when basic exit
/// reason == 39 (MONITOR). We don't need the address the guest is arming —
/// our MWAIT handler falls back to plain HLT, which wakes on any interrupt
/// regardless of memory-write triggers. Skip past the instruction.
#[inline]
pub fn handle_monitor(_guest_registers: &mut GuestRegisters, _vmx: &mut Vmx) -> ExitType {
    MONITOR_EXITS.fetch_add(1, Relaxed);
    ExitType::IncrementRIP
}
