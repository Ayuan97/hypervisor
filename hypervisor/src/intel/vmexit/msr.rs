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
    handle_msr_access_with(
        guest_registers,
        access_type,
        |msr| unsafe { msr::rdmsr(msr) },
        EventInjection::vmentry_inject_gp,
    )
}

fn handle_msr_access_with<R, G>(
    guest_registers: &mut GuestRegisters,
    access_type: MsrAccessType,
    read_msr: R,
    inject_gp: G,
) -> ExitType
where
    R: FnOnce(u32) -> u64,
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
        let value = read_msr(msr) & !FEATURE_CONTROL_HIDDEN_BITS;
        guest_registers.rax = value & 0xFFFF_FFFF;
        guest_registers.rdx = value >> 32;
        return ExitType::IncrementRIP;
    }

    // VMX capability MSRs (0x480-0x491) — read-only on bare metal.
    // Pass reads through to hardware; writes → #GP (matches bare metal).
    if vmx_capability_msr(msr) {
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

    #[test]
    fn out_of_range_rdmsr_injects_gp_instead_of_faking_zero() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x4000_0000;
        regs.rax = 0x1111;
        regs.rdx = 0x2222;
        let mut injected_error = None;

        let exit = handle_msr_access_with(
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

        let exit = handle_msr_access_with(
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

        let exit = handle_msr_access_with(
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

        let exit = handle_msr_access_with(
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

        let exit = handle_msr_access_with(
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

        let exit = handle_msr_access_with(
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

        let exit = handle_msr_access_with(
            &mut regs,
            MsrAccessType::Write,
            |_| panic!("Intel PT MSR write should not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(injected_error, None);
    }

    #[test]
    fn vmx_capability_rdmsr_passes_through_to_hardware() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x480; // IA32_VMX_BASIC

        let exit = handle_msr_access_with(
            &mut regs,
            MsrAccessType::Read,
            |_| 0xDEAD_BEEF_CAFE_BABE,
            |_| panic!("VMX MSR read should not inject #GP"),
        );

        assert_eq!(exit, ExitType::IncrementRIP);
        assert_eq!(regs.rax, 0xCAFE_BABE);
        assert_eq!(regs.rdx, 0xDEAD_BEEF);
    }

    #[test]
    fn vmx_capability_wrmsr_injects_gp() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x480;
        let mut injected_error = None;

        let exit = handle_msr_access_with(
            &mut regs,
            MsrAccessType::Write,
            |_| panic!("VMX MSR write should not reach hardware"),
            |code| injected_error = Some(code),
        );

        assert_eq!(exit, ExitType::Continue);
        assert_eq!(injected_error, Some(0));
    }

    #[test]
    fn sgx_keyhash_rdmsr_passes_through_to_hardware() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x8c;

        let exit = handle_msr_access_with(
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
