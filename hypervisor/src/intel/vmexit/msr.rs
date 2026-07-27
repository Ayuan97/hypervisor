//! Provides virtual machine management capabilities, specifically for handling MSR
//! read and write operations. It ensures that guest MSR accesses are properly
//! intercepted and handled, with support for injecting faults for unauthorized accesses.

use crate::{
    intel::{events::EventInjection, vmexit::ExitType},
    utils::capture::GuestRegisters,
};
use core::sync::atomic::{AtomicBool, AtomicU64};
use x86::{msr, time::rdtsc};

#[allow(clippy::declare_interior_mutable_const)]
const ZERO_U64: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::declare_interior_mutable_const)]
const ZERO_BOOL: AtomicBool = AtomicBool::new(false);

pub(super) const MAX_APERF_SHADOW_CPUS: usize = 64;
pub(super) static APERF_SHADOW_VALID: [AtomicBool; MAX_APERF_SHADOW_CPUS] =
    [ZERO_BOOL; MAX_APERF_SHADOW_CPUS];
pub(super) static APERF_LAST_RAW: [AtomicU64; MAX_APERF_SHADOW_CPUS] =
    [ZERO_U64; MAX_APERF_SHADOW_CPUS];
pub(super) static MPERF_LAST_RAW: [AtomicU64; MAX_APERF_SHADOW_CPUS] =
    [ZERO_U64; MAX_APERF_SHADOW_CPUS];
pub(super) static APERF_LAST_TSC: [AtomicU64; MAX_APERF_SHADOW_CPUS] =
    [ZERO_U64; MAX_APERF_SHADOW_CPUS];
pub(super) static APERF_LAST_HOST_TSC: [AtomicU64; MAX_APERF_SHADOW_CPUS] =
    [ZERO_U64; MAX_APERF_SHADOW_CPUS];
pub(super) static APERF_CORRECTION: [AtomicU64; MAX_APERF_SHADOW_CPUS] =
    [ZERO_U64; MAX_APERF_SHADOW_CPUS];
pub(super) static MPERF_CORRECTION: [AtomicU64; MAX_APERF_SHADOW_CPUS] =
    [ZERO_U64; MAX_APERF_SHADOW_CPUS];
pub(super) static APERF_OFFSET: [AtomicU64; MAX_APERF_SHADOW_CPUS] =
    [ZERO_U64; MAX_APERF_SHADOW_CPUS];
pub(super) static MPERF_OFFSET: [AtomicU64; MAX_APERF_SHADOW_CPUS] =
    [ZERO_U64; MAX_APERF_SHADOW_CPUS];

pub(super) fn aperf_mperf_shadow_enabled() -> bool {
    option_env!("HV_ENABLE_APERF_SHADOW").map_or(false, |v| v == "1")
}

const IA32_FEATURE_CONTROL_MSR: u32 = 0x3a;
const IA32_VMX_MSR_START: u32 = 0x480;
const IA32_VMX_MSR_END: u32 = 0x491;
const IA32_SGXLEPUBKEYHASH_MSR_START: u32 = 0x8c;
const IA32_SGXLEPUBKEYHASH_MSR_END: u32 = 0x8f;
const FEATURE_CONTROL_VMX_BITS: u64 = (1 << 1) | (1 << 2);
const FEATURE_CONTROL_SENTER_BITS: u64 = 0xff << 8;
const FEATURE_CONTROL_SGX_BITS: u64 = (1 << 17) | (1 << 18);
const FEATURE_CONTROL_HIDDEN_BITS: u64 =
    FEATURE_CONTROL_VMX_BITS | FEATURE_CONTROL_SENTER_BITS | FEATURE_CONTROL_SGX_BITS;
const IA32_RTIT_OUTPUT_BASE_MSR: u32 = 0x560;
const IA32_RTIT_OUTPUT_MASK_PTRS_MSR: u32 = 0x561;
const IA32_RTIT_CTL_MSR: u32 = 0x570;
const IA32_RTIT_STATUS_MSR: u32 = 0x571;
const IA32_RTIT_CR3_MATCH_MSR: u32 = 0x572;
const IA32_RTIT_ADDR_MSR_START: u32 = 0x580;
const IA32_RTIT_ADDR_MSR_END: u32 = 0x58f;
const IA32_MPERF: u32 = 0xE7;
const IA32_APERF: u32 = 0xE8;

/// Enum representing the type of MSR access.
///
/// There are two types of MSR access: reading from an MSR and writing to an MSR.
pub enum MsrAccessType {
    Read,
    Write,
}

/// Handles MSR access VM exits.
///
/// Handles intercepted MSR accesses.
///
/// The MSR bitmap intercepts only the virtualized capability surface:
/// IA32_FEATURE_CONTROL, VMX capability MSRs, hidden SGX key-hash MSRs, and
/// hidden Intel PT MSRs. Native architectural MSRs remain outside the bitmap.
pub fn handle_msr_access(
    guest_registers: &mut GuestRegisters,
    access_type: MsrAccessType,
) -> ExitType {
    use crate::intel::diag;
    use core::sync::atomic::Ordering::Relaxed;
    let msr_addr = guest_registers.rcx as u32;
    diag::LAST_MSR_ADDR.store(msr_addr as u64, Relaxed);
    match &access_type {
        MsrAccessType::Read => {
            diag::LAST_MSR_ACTION.store(0, Relaxed);
            diag::MSR_READ_COUNT.fetch_add(1, Relaxed);
        }
        MsrAccessType::Write => {
            diag::LAST_MSR_ACTION.store(1, Relaxed);
            diag::MSR_WRITE_COUNT.fetch_add(1, Relaxed);
        }
    }
    handle_msr_access_with(
        guest_registers,
        access_type,
        |msr| unsafe { msr::rdmsr(msr) },
        |msr, value| unsafe { msr::wrmsr(msr, value) },
        |code| {
            diag::MSR_GP_INJECTED.fetch_add(1, Relaxed);
            EventInjection::vmentry_inject_gp(code);
        },
    )
}

fn handle_msr_access_with<R, W, G>(
    guest_registers: &mut GuestRegisters,
    access_type: MsrAccessType,
    mut read_msr: R,
    mut write_msr: W,
    mut inject_gp: G,
) -> ExitType
where
    R: FnMut(u32) -> u64,
    W: FnMut(u32, u64),
    G: FnMut(u32),
{
    let msr = guest_registers.rcx as u32;

    // These MSRs belong to capabilities hidden by the CPUID model. Faulting
    // both directions keeps the feature leaves and MSR surface coherent.
    if intel_pt_msr_is_virtualized(msr) || sgx_keyhash_msr(msr) {
        inject_gp(0);
        return ExitType::Continue;
    }

    if aperf_mperf_shadow_enabled() && (msr == IA32_APERF || msr == IA32_MPERF) {
        match access_type {
            MsrAccessType::Read => {
                let raw_aperf = read_msr(IA32_APERF);
                let raw_mperf = read_msr(IA32_MPERF);
                let cpu = crate::intel::host_idt::current_cpu_index();
                let value = aperf_mperf_shadow_read(cpu, raw_aperf, raw_mperf, msr);
                guest_registers.rax = value & 0xFFFF_FFFF;
                guest_registers.rdx = value >> 32;
                if msr == IA32_APERF {
                    super::super::diag::APERF_READ_COUNT
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                } else {
                    super::super::diag::MPERF_READ_COUNT
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
                return ExitType::IncrementRIP;
            }
            MsrAccessType::Write => {
                let value = ((guest_registers.rdx as u64) << 32)
                    | (guest_registers.rax as u64 & 0xFFFF_FFFF);
                let cpu = crate::intel::host_idt::current_cpu_index();
                let raw_aperf = read_msr(IA32_APERF);
                let raw_mperf = read_msr(IA32_MPERF);
                if cpu < MAX_APERF_SHADOW_CPUS {
                    aperf_mperf_shadow_write(cpu, raw_aperf, raw_mperf, msr, value);
                } else {
                    // Keep the architectural operation working if the CPU
                    // index is outside the tracked range.
                    write_msr(msr, value);
                }
                return ExitType::IncrementRIP;
            }
        }
    }

    if matches!(access_type, MsrAccessType::Read) && msr == IA32_FEATURE_CONTROL_MSR {
        let raw = read_msr(msr);
        let value = if super::cpuid::transparent_mode_enabled(option_env!("HV_TRANSPARENT")) {
            raw
        } else {
            raw & !FEATURE_CONTROL_HIDDEN_BITS
        };
        guest_registers.rax = value & 0xFFFF_FFFF;
        guest_registers.rdx = value >> 32;
        return ExitType::IncrementRIP;
    }

    // VMX capability MSRs (0x480-0x491) — inject #GP for both reads and writes.
    //
    // Bare metal without VMX support returns #GP on RDMSR. With VMX support but
    // BIOS-locked disable (the stealth model we present via CPUID.1.ECX[5]=0),
    // reads *would* succeed with real values — but the CPUID/MSR mismatch is a
    // known EAC detection vector (secret.club 2020). Present a stricter but
    // consistent story: CPUID says no VMX → MSR reads also fault. Writes always
    // #GP because these MSRs are architecturally read-only per Intel SDM.
    if vmx_capability_msr(msr) {
        inject_gp(0);
        return ExitType::Continue;
    }

    // SGX key-hash MSRs (0x8C-0x8F) and IA32_FEATURE_CONTROL writes —
    // pass through reads; absorb or #GP writes as appropriate.
    // IA32_FEATURE_CONTROL write — bare metal #GPs when lock bit is set,
    // which it always is after BIOS. Inject #GP to match.
    if matches!(access_type, MsrAccessType::Write) && msr == IA32_FEATURE_CONTROL_MSR {
        inject_gp(0);
        return ExitType::Continue;
    }

    // ── P2 stealth MSRs (secret.club EAC detection vectors) ──

    // APERF / MPERF reach this path only when the optional shadow has added
    // them to the bitmap; the default build leaves them native.
    if msr == IA32_APERF || msr == IA32_MPERF {
        if matches!(access_type, MsrAccessType::Read) {
            let value = read_msr(msr);
            guest_registers.rax = value & 0xFFFF_FFFF;
            guest_registers.rdx = value >> 32;
            if msr == IA32_APERF {
                super::super::diag::APERF_READ_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            } else {
                super::super::diag::MPERF_READ_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            return ExitType::IncrementRIP;
        }
    }

    // MSR_PKG_CST_CONFIG_CONTROL (0xE2) is no longer intercepted — see
    // msr_bitmap.rs for the removal rationale. Any RDMSR/WRMSR on 0xE2
    // that reaches here would be a bug in the bitmap, so fall through
    // to the default #GP path below rather than silently pretending.

    // IA32_DEBUGCTL: route through the VMCS guest-state field, NOT bare
    // hardware. On VM-exit, Intel SDM 27.5.1 unconditionally clears the
    // *hardware* IA32_DEBUGCTL to 0; the guest's real value is saved to
    // GUEST_IA32_DEBUGCTL_FULL. vmcs.rs explicitly requires the matching
    // SAVE_DEBUG_CONTROLS / LOAD_DEBUG_CONTROLS pair. If we
    // read hardware here, the guest sees 0 no matter what they wrote.
    // If we write hardware here, VM-entry immediately overwrites it from
    // the guest area on the next VMRESUME so the guest still sees the
    // stale value. EAC probes DEBUGCTL specifically to check
    // write-then-read consistency — the old handler flunked that check,
    // exposing us as a hypervisor and triggering a bugcheck-IPI freeze.
    // LBR TOS and LBR stack: pass through both directions. Returning 0 on
    // read broke kernel LBR/BTB users at boot (2026-07-09 BSOD 0x50 at
    // fffff8057ea8086f). Counters still tell us if EAC polls LBR stack.
    inject_gp(0);
    ExitType::Continue
}

fn aperf_mperf_shadow_read(cpu: usize, raw_aperf: u64, raw_mperf: u64, msr: u32) -> u64 {
    if cpu >= MAX_APERF_SHADOW_CPUS {
        return if msr == IA32_APERF { raw_aperf } else { raw_mperf };
    }

    let now_tsc = unsafe { rdtsc() };
    let host_tsc = super::super::diag::host_tsc_accum(cpu);
    if APERF_SHADOW_VALID[cpu].load(core::sync::atomic::Ordering::Acquire) {
        let total_tsc = now_tsc
            .wrapping_sub(APERF_LAST_TSC[cpu].load(core::sync::atomic::Ordering::Relaxed));
        let host_delta = host_tsc
            .wrapping_sub(APERF_LAST_HOST_TSC[cpu].load(core::sync::atomic::Ordering::Relaxed))
            .min(total_tsc);
        if total_tsc != 0 && host_delta != 0 {
            let aperf_delta = raw_aperf
                .wrapping_sub(APERF_LAST_RAW[cpu].load(core::sync::atomic::Ordering::Relaxed));
            let mperf_delta = raw_mperf
                .wrapping_sub(MPERF_LAST_RAW[cpu].load(core::sync::atomic::Ordering::Relaxed));
            APERF_CORRECTION[cpu].fetch_add(
                proportional_counter_delta(aperf_delta, host_delta, total_tsc),
                core::sync::atomic::Ordering::Relaxed,
            );
            MPERF_CORRECTION[cpu].fetch_add(
                proportional_counter_delta(mperf_delta, host_delta, total_tsc),
                core::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    APERF_LAST_RAW[cpu].store(raw_aperf, core::sync::atomic::Ordering::Relaxed);
    MPERF_LAST_RAW[cpu].store(raw_mperf, core::sync::atomic::Ordering::Relaxed);
    APERF_LAST_TSC[cpu].store(now_tsc, core::sync::atomic::Ordering::Relaxed);
    APERF_LAST_HOST_TSC[cpu].store(host_tsc, core::sync::atomic::Ordering::Relaxed);
    APERF_SHADOW_VALID[cpu].store(true, core::sync::atomic::Ordering::Release);

    if msr == IA32_APERF {
        shadow_visible_value(
            raw_aperf,
            APERF_CORRECTION[cpu].load(core::sync::atomic::Ordering::Relaxed),
            APERF_OFFSET[cpu].load(core::sync::atomic::Ordering::Relaxed),
        )
    } else {
        shadow_visible_value(
            raw_mperf,
            MPERF_CORRECTION[cpu].load(core::sync::atomic::Ordering::Relaxed),
            MPERF_OFFSET[cpu].load(core::sync::atomic::Ordering::Relaxed),
        )
    }
}

fn aperf_mperf_shadow_write(
    cpu: usize,
    raw_aperf: u64,
    raw_mperf: u64,
    msr: u32,
    value: u64,
) {
    let now_tsc = unsafe { rdtsc() };
    let host_tsc = super::super::diag::host_tsc_accum(cpu);
    let correction = if msr == IA32_APERF {
        APERF_CORRECTION[cpu].load(core::sync::atomic::Ordering::Relaxed)
    } else {
        MPERF_CORRECTION[cpu].load(core::sync::atomic::Ordering::Relaxed)
    };
    let raw = if msr == IA32_APERF { raw_aperf } else { raw_mperf };
    let offset = shadow_offset_for_write(value, raw, correction);
    if msr == IA32_APERF {
        APERF_OFFSET[cpu].store(offset, core::sync::atomic::Ordering::Relaxed);
    } else {
        MPERF_OFFSET[cpu].store(offset, core::sync::atomic::Ordering::Relaxed);
    }
    APERF_LAST_RAW[cpu].store(raw_aperf, core::sync::atomic::Ordering::Relaxed);
    MPERF_LAST_RAW[cpu].store(raw_mperf, core::sync::atomic::Ordering::Relaxed);
    APERF_LAST_TSC[cpu].store(now_tsc, core::sync::atomic::Ordering::Relaxed);
    APERF_LAST_HOST_TSC[cpu].store(host_tsc, core::sync::atomic::Ordering::Relaxed);
    APERF_SHADOW_VALID[cpu].store(true, core::sync::atomic::Ordering::Release);
}

#[inline]
fn shadow_visible_value(raw: u64, correction: u64, offset: u64) -> u64 {
    raw.wrapping_sub(correction).wrapping_add(offset)
}

#[inline]
fn shadow_offset_for_write(value: u64, raw: u64, correction: u64) -> u64 {
    value.wrapping_sub(raw.wrapping_sub(correction))
}

fn proportional_counter_delta(counter_delta: u64, part: u64, whole: u64) -> u64 {
    ((counter_delta as u128 * part as u128) / whole as u128) as u64
}

fn vmx_capability_msr(msr: u32) -> bool {
    (IA32_VMX_MSR_START..=IA32_VMX_MSR_END).contains(&msr)
}

fn sgx_keyhash_msr(msr: u32) -> bool {
    (IA32_SGXLEPUBKEYHASH_MSR_START..=IA32_SGXLEPUBKEYHASH_MSR_END).contains(&msr)
}

fn intel_pt_msr_is_virtualized(msr: u32) -> bool {
    matches!(
        msr,
        IA32_RTIT_OUTPUT_BASE_MSR
            | IA32_RTIT_OUTPUT_MASK_PTRS_MSR
            | IA32_RTIT_CTL_MSR
            | IA32_RTIT_STATUS_MSR
            | IA32_RTIT_CR3_MATCH_MSR
    ) || (IA32_RTIT_ADDR_MSR_START..=IA32_RTIT_ADDR_MSR_END).contains(&msr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: forwards to `handle_msr_access_with` with a no-op write_msr
    /// closure. Lets existing 4-arg tests keep their signature.
    fn handle_msr_access_test<R, G>(
        guest_registers: &mut GuestRegisters,
        access_type: MsrAccessType,
        read_msr: R,
        inject_gp: G,
    ) -> ExitType
    where
        R: FnMut(u32) -> u64,
        G: FnMut(u32),
    {
        handle_msr_access_with(guest_registers, access_type, read_msr, |_, _| (), inject_gp)
    }

    #[test]
    fn out_of_range_rdmsr_injects_gp_instead_of_faking_zero() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x4000_0000;
        regs.rax = 0x1111;
        regs.rdx = 0x2222;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |_| 0,
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::Continue);
        assert_eq!(injected_error, Some(0));
        assert_eq!(regs.rax, 0x1111);
        assert_eq!(regs.rdx, 0x2222);
    }

    #[test]
    fn out_of_range_wrmsr_injects_gp_without_advancing_rip() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x4000_0000;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Write,
            |_| 0,
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::Continue);
        assert_eq!(injected_error, Some(0));
    }

    #[test]
    fn feature_control_rdmsr_hides_vmx_enable_bits() {
        let mut regs = GuestRegisters::default();
        regs.rcx = IA32_FEATURE_CONTROL_MSR as u64;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |_| 0x1234_0000_0000_0007,
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(injected_error, None);
        assert_eq!(regs.rax, 0x0000_0001);
        assert_eq!(regs.rdx, 0x1234_0000);
    }

    #[test]
    fn feature_control_rdmsr_hides_senter_and_sgx_enable_bits() {
        let mut regs = GuestRegisters::default();
        regs.rcx = IA32_FEATURE_CONTROL_MSR as u64;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |_| 0xffff_ffff_ffff_ffff,
            |_| panic!("feature control read should not inject #GP"),
        );

        let value = regs.rax | (regs.rdx << 32);
        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(value & FEATURE_CONTROL_HIDDEN_BITS, 0);
        assert_ne!(value & 1, 0);
    }

    #[test]
    fn hidden_intel_pt_rdmsr_injects_gp() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x570;
        regs.rax = 0x1111;
        regs.rdx = 0x2222;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |_| panic!("Intel PT MSR read should not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::Continue);
        assert_eq!(injected_error, Some(0));
        assert_eq!(regs.rax, 0x1111);
        assert_eq!(regs.rdx, 0x2222);
    }

    #[test]
    fn aperf_correction_scales_with_host_time() {
        assert_eq!(proportional_counter_delta(1_000, 25, 100), 250);
    }

    #[test]
    fn aperf_shadow_write_round_trips_after_correction() {
        let desired = 77;
        let offset = shadow_offset_for_write(desired, 1_000, 250);
        assert_eq!(shadow_visible_value(1_000, 250, offset), desired);
    }

    #[test]
    fn hidden_intel_pt_wrmsr_injects_gp() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x570;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Write,
            |_| panic!("Intel PT MSR write should not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::Continue);
        assert_eq!(injected_error, Some(0));
    }

    #[test]
    fn vmx_capability_rdmsr_injects_gp_to_match_hidden_vmx_bit() {
        // With CPUID.1.ECX[5] cleared (VMX bit hidden), leaking real values
        // from VMX capability MSRs would create a detectable inconsistency
        // (see docs/eac-hv-research-2026-07.md, secret.club analysis).
        // Present a consistent "no VMX" story by injecting #GP on read.
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x480; // IA32_VMX_BASIC
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |_| panic!("VMX MSR read must not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::Continue);
        assert_eq!(injected_error, Some(0));
    }

    #[test]
    fn vmx_capability_wrmsr_injects_gp() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x480;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Write,
            |_| panic!("VMX MSR write should not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::Continue);
        assert_eq!(injected_error, Some(0));
    }

    #[test]
    fn aperf_and_mperf_reads_pass_through() {
        for msr in [IA32_APERF, IA32_MPERF] {
            let mut regs = GuestRegisters::default();
            regs.rcx = msr as u64;
            let exit = handle_msr_access_test(
                &mut regs,
                MsrAccessType::Read,
                |_| 0xCAFE_BABE_DEAD_BEEF,
                |_| panic!("APERF/MPERF read must not #GP for {:#x}", msr),
            );
            assert_eq!(exit, ExitType::IncrementRIP);
            assert_eq!(regs.rax, 0xDEAD_BEEF);
            assert_eq!(regs.rdx, 0xCAFE_BABE);
        }
    }

    // DEBUGCTL read/write now bypass the `read_msr`/`write_msr` closures
    // entirely: they go through `support::vmread_checked` /
    // `vmwrite_checked` on the VMCS guest-state field, which the unit
    // tests can't mock without a live VMCS. Exercise this path in the
    // Windows integration self-check (`cpuid_ping` DEBUGCTL counters
    // reflect that guest writes now round-trip back correctly) instead.

    #[test]
    fn vmx_capability_msr_range_boundary_all_reads_gp() {
        // Full IA32_VMX_MSR_START..=IA32_VMX_MSR_END range should GP on read.
        for msr in [
            IA32_VMX_MSR_START,
            0x485,
            0x489,
            IA32_VMX_MSR_END,
        ] {
            let mut regs = GuestRegisters::default();
            regs.rcx = msr as u64;
            let mut injected_error = None;
            let exit = handle_msr_access_test(
                &mut regs,
                MsrAccessType::Read,
                |_| panic!("VMX MSR read must not reach hardware for {:#x}", msr),
                |code| injected_error = Some(code),
            );
            assert_eq!(exit, ExitType::Continue, "msr {:#x}", msr);
            assert_eq!(injected_error, Some(0), "msr {:#x}", msr);
        }
    }

    #[test]
    fn hidden_sgx_keyhash_rdmsr_injects_gp() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x8c;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |_| panic!("SGX keyhash MSR read must not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::Continue);
        assert_eq!(injected_error, Some(0));
    }
}
