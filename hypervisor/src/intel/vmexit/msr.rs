//! Provides virtual machine management capabilities, specifically for handling MSR
//! read and write operations. It ensures that guest MSR accesses are properly
//! intercepted and handled, with support for injecting faults for unauthorized accesses.

use crate::{
    intel::{events::EventInjection, vmexit::ExitType},
    utils::capture::GuestRegisters,
};
use x86::msr;

const IA32_FEATURE_CONTROL_MSR: u32 = 0x3a;
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
/// MSR bitmap is all-zeros, so MSRs in 0x0-0x1FFF and 0xC0000000-0xC0001FFF
/// pass through without VM exit. Only out-of-range MSRs reach here (Intel SDM
/// 25.1.3). Native rdmsr/wrmsr in VMX root for non-existent MSRs → #GP → BSOD.
/// Out-of-range RDMSR/WRMSR should behave like hardware and raise #GP. Silently
/// returning zero makes kernel probes observe non-native behavior.
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

    if matches!(access_type, MsrAccessType::Read) && msr == IA32_FEATURE_CONTROL_MSR {
        let value = read_msr(msr) & !FEATURE_CONTROL_HIDDEN_BITS;
        guest_registers.rax = value & 0xFFFF_FFFF;
        guest_registers.rdx = value >> 32;
        return ExitType::IncrementRIP;
    }

    inject_gp(0);
    ExitType::Continue
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
}
