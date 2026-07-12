//! EPT-execute hook on `nt!KeBugCheckEx` — is bugcheck actually being entered?
//!
//! `observe_guest_rip_for_bugcheck` in `diag.rs` only fires when a VM-exit
//! happens while guest RIP is inside KeBugCheckEx. Bugcheck rarely triggers
//! intercepted instructions (its first APIC IPI goes via WRMSR to a MSR we
//! do not intercept), so HITS stays 0 no matter what. That leaves us unable
//! to tell "EAC never triggered bugcheck" from "bugcheck ran but hung before
//! finishing" — both look identical from outside.
//!
//! Fix: mark the 4 KiB EPT page containing `KeBugCheckEx` as non-executable.
//! The first time any code on that page runs, an EPT-violation VM-exit fires
//! and we inspect guest RIP:
//!   - Within the KeBugCheckEx function body → confirmed entry. Record the
//!     hit to CMOS + statics and permanently re-grant execute (we only need
//!     one hit to answer the question).
//!   - Elsewhere on the same 4 KiB (a neighbouring nt!Ke* function) → temp
//!     re-grant execute, enable MTF, single-step, then re-cloak.
//!
//! No secondary EPT / dual-VMCS gymnastics — we mutate the primary EPT in
//! place. Serialisation across CPUs is provided by INVEPT-all-contexts after
//! each mutation.

use {
    crate::{
        error::HypervisorError,
        intel::{
            diag,
            ept::paging::{AccessType, Ept},
            invept::invept_all_contexts,
        },
        utils::{addresses::PhysicalAddress, nt::get_ntoskrnl_export},
    },
    core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    x86::current::paging::BASE_PAGE_SIZE,
};

const PAGE_MASK: u64 = !(BASE_PAGE_SIZE as u64 - 1);

/// Physical address of the 4 KiB page we cloaked (page-aligned). 0 means the
/// hook was never installed (init failure or address resolution failure).
pub static HOOK_PAGE_PA: AtomicU64 = AtomicU64::new(0);

/// Virtual address of nt!KeBugCheckEx's first instruction (for range check).
pub static HOOK_FN_START_VA: AtomicU64 = AtomicU64::new(0);

/// End of the range we consider "inside KeBugCheckEx". Set conservatively —
/// see `KEBUGCHECKEX_WATCH_LEN` in diag.rs. We match `guest_rip` in
/// [FN_START_VA, FN_START_VA + WATCH_LEN).
pub static HOOK_FN_END_VA: AtomicU64 = AtomicU64::new(0);

/// TSC of the first confirmed hit (0 = never). Set once, never overwritten.
pub static HOOK_FIRED_TSC: AtomicU64 = AtomicU64::new(0);

/// Guest RIP of the first confirmed hit.
pub static HOOK_FIRED_RIP: AtomicU64 = AtomicU64::new(0);

/// CPU index of the first confirmed hit.
pub static HOOK_FIRED_CPU: AtomicU64 = AtomicU64::new(0);

/// Count of spurious EPT-violations on our cloaked page (neighbouring
/// functions on the same 4 KiB executed and had to be single-stepped).
pub static HOOK_SPURIOUS_COUNT: AtomicU64 = AtomicU64::new(0);

/// Set to true once the confirmed hit has been recorded — after this the
/// cloak is permanently lifted (X=1) and we no longer intercept.
static HOOK_LATCHED: AtomicBool = AtomicBool::new(false);

const WATCH_LEN: u64 = 128; // same conservative window diag.rs uses

/// Default: hook installation is SKIPPED. Opt in at compile time with
/// `HV_ENABLE_ENTRY_HOOK=1 cargo build ...` when you specifically want the
/// KeBugCheckEx-entered diagnostic and are willing to pay for it.
///
/// Why the flip (2026-07-13): the hook cloaks the entire 4 KiB page holding
/// KeBugCheckEx and single-steps every neighbour function that also lives on
/// that page. Under an EAC-driven workload that scales to ~1.5M spurious
/// step-throughs per session (measured via HOOK_SPURIOUS_COUNT), each one
/// costing an EPT-violation exit + MTF exit + two INVEPTs. That overhead is
/// the leading suspect for the "HV alone + EAC = freeze inside minutes"
/// pattern we've been chasing — CPUs sink into the step-through loop and
/// starve IPI delivery until Windows watchdog can't cope.
///
/// The old default matched the tooling's ergonomics — "just build, hook
/// works" — but the ergonomics aren't worth the freezes, and the CTL id
/// 70-76 sentinels still return their "all zero" no-hit state when disabled
/// so cpuid_ping doesn't need to know either way.
const HOOK_DISABLED: bool = option_env!("HV_ENABLE_ENTRY_HOOK").is_none();

/// Resolve KeBugCheckEx, split the containing 2 MiB EPT entry, and cloak
/// the 4 KiB page (READ_WRITE only — no execute). Idempotent: if the
/// address cannot be resolved or the page split fails, the hook is simply
/// left disabled (HOOK_PAGE_PA stays 0). Never fatal to driver init.
pub fn install(ept: &mut Ept) {
    if HOOK_DISABLED {
        log::info!("bugcheck_hook: HV_ENABLE_ENTRY_HOOK not set, install skipped");
        return;
    }
    let addr = get_ntoskrnl_export("KeBugCheckEx");
    if addr.is_null() {
        log::warn!("bugcheck_hook: KeBugCheckEx resolution failed, hook disabled");
        return;
    }
    let va = addr as usize as u64;
    let pa = PhysicalAddress::pa_from_va(va);
    if pa == 0 {
        log::warn!("bugcheck_hook: PA resolution failed for VA {:#x}, hook disabled", va);
        return;
    }
    let page_pa = pa & PAGE_MASK;

    // The identity map covers 0..512 GiB with 2 MiB pages, so the page
    // containing KeBugCheckEx is still a large mapping — split it first.
    if let Err(e) = ept.split_2mb_to_4kb(page_pa, AccessType::READ_WRITE_EXECUTE) {
        log::warn!(
            "bugcheck_hook: split 2MB @ {:#x} failed ({:?}), hook disabled",
            page_pa & !((2u64 << 20) - 1),
            e
        );
        return;
    }

    // Now cloak the single 4 KiB page containing KeBugCheckEx: READ_WRITE
    // (no EXECUTE). Any instruction fetch on this page will EPT-violate.
    if let Err(e) = ept.set_page_access(page_pa, AccessType::READ_WRITE) {
        log::warn!(
            "bugcheck_hook: set_page_access(no-X) failed ({:?}), hook disabled",
            e
        );
        return;
    }

    HOOK_PAGE_PA.store(page_pa, Relaxed);
    HOOK_FN_START_VA.store(va, Relaxed);
    HOOK_FN_END_VA.store(va.saturating_add(WATCH_LEN), Relaxed);
    log::info!(
        "bugcheck_hook: installed va={:#x} page_pa={:#x}",
        va,
        page_pa
    );
}

/// True iff the given guest physical address falls on the cloaked page and
/// the hook has not yet been latched. Fast, no-alloc, safe to call from EPT
/// violation handler.
#[inline]
pub fn matches(guest_pa: u64) -> bool {
    let hook_pa = HOOK_PAGE_PA.load(Relaxed);
    if hook_pa == 0 || HOOK_LATCHED.load(Relaxed) {
        return false;
    }
    (guest_pa & PAGE_MASK) == hook_pa
}

/// True iff `rip` is inside the KeBugCheckEx watch window.
#[inline]
fn rip_matches_kebugcheckex(rip: u64) -> bool {
    let start = HOOK_FN_START_VA.load(Relaxed);
    let end = HOOK_FN_END_VA.load(Relaxed);
    start != 0 && rip >= start && rip < end
}

/// Confirmed hit path — record everything we can and permanently re-grant
/// execute on the cloaked page. After this, `matches()` returns false and
/// the hook is done for the rest of the session.
fn latch_and_uncloak(ept: &mut Ept, page_pa: u64, guest_rip: u64) {
    let cpu = current_cpu_index();
    let tsc = rdtsc_now();
    HOOK_FIRED_TSC.store(tsc, Relaxed);
    HOOK_FIRED_RIP.store(guest_rip, Relaxed);
    HOOK_FIRED_CPU.store(cpu, Relaxed);
    diag::note_bugcheck_entry_hook_fired();
    HOOK_LATCHED.store(true, Relaxed);
    // Restore execute so the next iteration (and every future one) proceeds
    // normally. If this fails we log and swallow — the hit is already
    // recorded; letting the fetch fault is worse than trying again later.
    if let Err(e) = ept.set_page_access(page_pa, AccessType::READ_WRITE_EXECUTE) {
        log::error!(
            "bugcheck_hook: latch uncloak failed ({:?}) — guest may fault",
            e
        );
    }
}

/// Spurious hit path — guest RIP is outside KeBugCheckEx but on the same
/// 4 KiB page. Temporarily re-grant execute, ask the caller to set MTF, and
/// remember to re-cloak on the ensuing MTF exit.
fn allow_step(ept: &mut Ept, page_pa: u64) -> Result<(), HypervisorError> {
    HOOK_SPURIOUS_COUNT.fetch_add(1, Relaxed);
    ept.set_page_access(page_pa, AccessType::READ_WRITE_EXECUTE)
}

/// Called at the end of the MTF handler if `Vmx::bugcheck_hook_mtf_recloak`
/// is set — re-cloak the hook page (unless meanwhile latched).
pub fn recloak_after_step(ept: &mut Ept) {
    if HOOK_LATCHED.load(Relaxed) {
        return;
    }
    let page_pa = HOOK_PAGE_PA.load(Relaxed);
    if page_pa == 0 {
        return;
    }
    if let Err(e) = ept.set_page_access(page_pa, AccessType::READ_WRITE) {
        log::error!("bugcheck_hook: recloak after MTF failed ({:?})", e);
    }
}

/// Result of `check_ept_violation`.
pub enum HookOutcome {
    /// Not our page — caller should handle the violation as usual.
    NotOurs,
    /// Handled fully (confirmed hit + latched). Caller should resume guest.
    Latched,
    /// Handled: page temporarily executable. Caller must enable MTF and set
    /// `Vmx::bugcheck_hook_mtf_recloak = true` so we re-cloak on MTF exit.
    NeedsStep,
}

pub fn check_ept_violation(guest_pa: u64, guest_rip: u64, ept: &mut Ept) -> HookOutcome {
    if !matches(guest_pa) {
        return HookOutcome::NotOurs;
    }
    let page_pa = HOOK_PAGE_PA.load(Relaxed);
    if rip_matches_kebugcheckex(guest_rip) {
        latch_and_uncloak(ept, page_pa, guest_rip);
        invept_all_contexts();
        HookOutcome::Latched
    } else {
        if allow_step(ept, page_pa).is_err() {
            return HookOutcome::NotOurs;
        }
        invept_all_contexts();
        HookOutcome::NeedsStep
    }
}

// --- small helpers duplicated from diag.rs to avoid making them pub there ---

#[inline]
fn current_cpu_index() -> u64 {
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
    (aux & 0xFF) as u64
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
