//! Provides virtual machine management capabilities, specifically for handling MSR
//! read and write operations. It ensures that guest MSR accesses are properly
//! intercepted and handled, with support for injecting faults for unauthorized accesses.

use crate::{
    intel::{events::EventInjection, vmexit::ExitType},
    utils::capture::GuestRegisters,
};
use x86::msr;

const IA32_FEATURE_CONTROL_MSR: u32 = 0x3a;
const IA32_TSC_AUX: u32 = 0xC000_0103;
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
const IA32_EFER: u32 = 0xC000_0080;
const IA32_MPERF: u32 = 0xE7;
const IA32_APERF: u32 = 0xE8;
const IA32_DEBUGCTL: u32 = 0x1D9;
const IA32_LASTBRANCH_TOS: u32 = 0x1C9;
const IA32_LBR_STACK_START: u32 = 0x680;
const IA32_LBR_STACK_END: u32 = 0x6BF;

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
/// The MSR bitmap intercepts specific MSRs: IA32_FEATURE_CONTROL, VMX
/// capability MSRs, SGX key-hash MSRs, Intel PT MSRs, and IA32_TSC_AUX.
/// Reads are passed through to hardware (hiding VMX bits where needed);
/// writes to read-only MSRs inject #GP to match bare-metal behavior.
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
    read_msr: R,
    write_msr: W,
    inject_gp: G,
) -> ExitType
where
    R: FnOnce(u32) -> u64,
    W: FnOnce(u32, u64),
    G: FnOnce(u32),
{
    let msr = guest_registers.rcx as u32;

    if intel_pt_msr_is_virtualized(msr) {
        if matches!(access_type, MsrAccessType::Read) {
            guest_registers.rax = 0;
            guest_registers.rdx = 0;
        }
        return ExitType::IncrementRIP;
    }

    if matches!(access_type, MsrAccessType::Write) && msr == IA32_TSC_AUX {
        return ExitType::IncrementRIP;
    }

    if matches!(access_type, MsrAccessType::Read) && msr == IA32_FEATURE_CONTROL_MSR {
        let raw = read_msr(msr);
        let value = if option_env!("HV_TRANSPARENT").is_some() {
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
    if sgx_keyhash_msr(msr) {
        match access_type {
            MsrAccessType::Read => {
                let value = read_msr(msr);
                guest_registers.rax = value & 0xFFFF_FFFF;
                guest_registers.rdx = value >> 32;
                return ExitType::IncrementRIP;
            }
            MsrAccessType::Write => {
                inject_gp(0);
                return ExitType::Continue;
            }
        }
    }

    // IA32_FEATURE_CONTROL write — bare metal #GPs when lock bit is set,
    // which it always is after BIOS. Inject #GP to match.
    if matches!(access_type, MsrAccessType::Write) && msr == IA32_FEATURE_CONTROL_MSR {
        inject_gp(0);
        return ExitType::Continue;
    }

    // ── P2 stealth MSRs (secret.club EAC detection vectors) ──

    // IA32_EFER: pass through both directions. Guest sees real SCE bit so
    // syscall works; counting reads reveals whether EAC is polling EFER for
    // its 30-min syscall-hook check.
    if msr == IA32_EFER {
        match access_type {
            MsrAccessType::Read => {
                let value = read_msr(msr);
                guest_registers.rax = value & 0xFFFF_FFFF;
                guest_registers.rdx = value >> 32;
                super::super::diag::EFER_READ_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return ExitType::IncrementRIP;
            }
            MsrAccessType::Write => {
                let value =
                    ((guest_registers.rdx as u64) << 32) | (guest_registers.rax as u64 & 0xFFFF_FFFF);
                write_msr(msr, value);
                super::super::diag::EFER_WRITE_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return ExitType::IncrementRIP;
            }
        }
    }

    // APERF / MPERF: pass through reads (very low VM-exit rate means ratio
    // stays close to bare metal). Just count so we can tell if EAC polls
    // them — writes are not intercepted at all.
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

    // IA32_DEBUGCTL: guest read gets back a shadow (initially 0), guest
    // write is virtualized (stored in shadow, not applied to hardware) so
    // host code that runs between VM-exit and VM-entry does not corrupt LBR
    // state from the guest's point of view.
    if msr == IA32_DEBUGCTL {
        match access_type {
            MsrAccessType::Read => {
                let shadow = super::super::diag::LBR_DEBUGCTL_SHADOW
                    .load(core::sync::atomic::Ordering::Relaxed);
                guest_registers.rax = shadow & 0xFFFF_FFFF;
                guest_registers.rdx = shadow >> 32;
                super::super::diag::DEBUGCTL_READ_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return ExitType::IncrementRIP;
            }
            MsrAccessType::Write => {
                let value =
                    ((guest_registers.rdx as u64) << 32) | (guest_registers.rax as u64 & 0xFFFF_FFFF);
                super::super::diag::LBR_DEBUGCTL_SHADOW
                    .store(value, core::sync::atomic::Ordering::Relaxed);
                super::super::diag::DEBUGCTL_WRITE_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return ExitType::IncrementRIP;
            }
        }
    }

    // LBR TOS and LBR stack: return 0 on read, silently absorb writes. This
    // hides any host branches that may have leaked into LBR while the
    // handler was running.
    if msr == IA32_LASTBRANCH_TOS
        || (IA32_LBR_STACK_START..=IA32_LBR_STACK_END).contains(&msr)
    {
        match access_type {
            MsrAccessType::Read => {
                guest_registers.rax = 0;
                guest_registers.rdx = 0;
                super::super::diag::LBR_STACK_READ_COUNT
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return ExitType::IncrementRIP;
            }
            MsrAccessType::Write => {
                return ExitType::IncrementRIP;
            }
        }
    }

    inject_gp(0);
    ExitType::Continue
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
        R: FnOnce(u32) -> u64,
        G: FnOnce(u32),
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
    fn intel_pt_rdmsr_returns_disabled_state() {
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

        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(injected_error, None);
        assert_eq!(regs.rax, 0);
        assert_eq!(regs.rdx, 0);
    }

    #[test]
    fn tsc_aux_wrmsr_is_silently_absorbed() {
        let mut regs = GuestRegisters::default();
        regs.rcx = IA32_TSC_AUX as u64;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Write,
            |_| panic!("TSC_AUX write should not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(injected_error, None);
    }

    #[test]
    fn intel_pt_wrmsr_is_ignored_without_faulting() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x570;
        let mut injected_error = None;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Write,
            |_| panic!("Intel PT MSR write should not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(injected_error, None);
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
    fn efer_read_passes_through_hardware_value() {
        let mut regs = GuestRegisters::default();
        regs.rcx = IA32_EFER as u64;
        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |m| {
                assert_eq!(m, IA32_EFER);
                0xDEAD_BEEF_1234_5678
            },
            |_| panic!("EFER read must not #GP"),
        );
        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(regs.rax, 0x1234_5678);
        assert_eq!(regs.rdx, 0xDEAD_BEEF);
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

    #[test]
    fn debugctl_read_returns_zero_shadow_by_default() {
        crate::intel::diag::LBR_DEBUGCTL_SHADOW.store(0, core::sync::atomic::Ordering::Relaxed);
        let mut regs = GuestRegisters::default();
        regs.rcx = IA32_DEBUGCTL as u64;
        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |_| panic!("DEBUGCTL must not read hardware"),
            |_| panic!("DEBUGCTL read must not #GP"),
        );
        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(regs.rax, 0);
        assert_eq!(regs.rdx, 0);
    }

    #[test]
    fn debugctl_write_stores_shadow_not_hardware() {
        crate::intel::diag::LBR_DEBUGCTL_SHADOW.store(0, core::sync::atomic::Ordering::Relaxed);
        let mut regs = GuestRegisters::default();
        regs.rcx = IA32_DEBUGCTL as u64;
        regs.rax = 0x0000_00FF;
        regs.rdx = 0x1122_3344;
        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Write,
            |_| panic!("DEBUGCTL write must not touch hardware"),
            |_| panic!("DEBUGCTL write must not #GP"),
        );
        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(
            crate::intel::diag::LBR_DEBUGCTL_SHADOW
                .load(core::sync::atomic::Ordering::Relaxed),
            0x1122_3344_0000_00FF
        );
    }

    #[test]
    fn lbr_stack_reads_return_zero_and_writes_are_silently_absorbed() {
        for msr in [IA32_LASTBRANCH_TOS, IA32_LBR_STACK_START, 0x69F, IA32_LBR_STACK_END] {
            let mut regs = GuestRegisters::default();
            regs.rcx = msr as u64;
            let read_exit = handle_msr_access_test(
                &mut regs,
                MsrAccessType::Read,
                |_| panic!("LBR stack must not read hardware for {:#x}", msr),
                |_| panic!("LBR stack read must not #GP"),
            );
            assert_eq!(read_exit, ExitType::IncrementRIP);
            assert_eq!(regs.rax, 0);
            assert_eq!(regs.rdx, 0);

            let mut regs = GuestRegisters::default();
            regs.rcx = msr as u64;
            regs.rax = 0xdead;
            let write_exit = handle_msr_access_test(
                &mut regs,
                MsrAccessType::Write,
                |_| panic!("LBR stack write must not reach hardware"),
                |_| panic!("LBR stack write must not #GP"),
            );
            assert_eq!(write_exit, ExitType::IncrementRIP);
        }
    }

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
    fn sgx_keyhash_rdmsr_passes_through_to_hardware() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x8c;

        let exit = handle_msr_access_test(
            &mut regs,
            MsrAccessType::Read,
            |_| 0x1122_3344_5566_7788,
            |_| panic!("SGX keyhash MSR read should not inject #GP"),
        );

        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(regs.rax, 0x5566_7788);
        assert_eq!(regs.rdx, 0x1122_3344);
    }
}
