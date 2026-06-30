//! Handles CPU-related virtualization tasks, specifically intercepting and managing
//! the `CPUID` instruction in a VM to control the exposure of CPU features to the guest.

#![allow(dead_code)]

use {
    super::vmcall::{dispatch_command, CPUID_COMM_LEAF, VMCALL_MAGIC},
    crate::{
        intel::{support::vmwrite_checked, vmexit::ExitType, vmx::Vmx},
        utils::capture::GuestRegisters,
    },
    bitfield::BitMut,
    x86::{
        cpuid::{cpuid, CpuIdResult},
        vmx::vmcs,
    },
};

const CPUID_TSC_COMPENSATION_CYCLES: u64 = 600;
const MAX_CPUID_TSC_COMPENSATION_CYCLES: u64 = 5_000_000;
const ENABLE_DYNAMIC_CPUID_TSC_COMPENSATION: bool = false;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Enum representing the various CPUID leaves for feature and interface discovery.
/// Reference: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
enum CpuidLeaf {
    /// CPUID function number to retrieve the processor's vendor identification string.
    VendorInfo = 0x0,

    /// CPUID function for feature information, including hypervisor presence.
    FeatureInformation = 0x1,

    /// CPUID function for extended feature information.
    ExtendedFeatureInformation = 0x7,

    /// Hypervisor vendor information leaf.
    HypervisorVendor = 0x40000000,

    /// Hypervisor interface identification leaf.
    HypervisorInterface = 0x40000001,

    /// Hypervisor system identity information leaf.
    HypervisorSystemIdentity = 0x40000002,

    /// Hypervisor feature identification leaf.
    HypervisorFeatureIdentification = 0x40000003,

    /// Hypervisor implementation recommendations leaf.
    ImplementationRecommendations = 0x40000004,

    /// Hypervisor implementation limits leaf.
    HypervisorImplementationLimits = 0x40000005,

    /// Hardware-specific features in use by the hypervisor leaf.
    ImplementationHardwareFeatures = 0x40000006,

    /// Nested hypervisor feature identification leaf.
    NestedHypervisorFeatureIdentification = 0x40000009,

    /// Nested virtualization features available leaf.
    HypervisorNestedVirtualizationFeatures = 0x4000000A,

    /// SGX capability leaf.
    SgxCapabilities = 0x12,
}

/// Enumerates specific feature bits in the ECX register for CPUID instruction results.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum FeatureBits {
    /// Bit 5 of ECX for CPUID with EAX=1, indicating VMX support.
    HypervisorVmxSupportBit = 5,
    /// Bit 6 of ECX for CPUID with EAX=1, indicating Safer Mode Extensions.
    SaferModeExtensionsBit = 6,
    /// Bit 31 of ECX for CPUID with EAX=1, indicating hypervisor presence.
    HypervisorPresentBit = 31,
}

/// Handles the `CPUID` VM-exit.
///
/// This function is invoked when the guest executes the `CPUID` instruction.
/// The handler retrieves the results of the `CPUID` instruction executed on
/// the host and then modifies or masks certain bits, if necessary, before
/// returning the results to the guest.
///
/// # Arguments
///
/// * `registers` - A mutable reference to the guest's current register state.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `CPUID` instruction in the VM.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual, Table C-1. Basic Exit Reasons 10.
#[rustfmt::skip]
pub fn handle_cpuid(guest_registers: &mut GuestRegisters, vmx: &mut Vmx) -> ExitType {
    log::trace!("Handling CPUID VM exit...");

    let leaf = guest_registers.rax as u32;

    if leaf == CPUID_COMM_LEAF && cpuid_comm_authorized(guest_registers) {
        return dispatch_command(guest_registers, vmx);
    }

    if ENABLE_DYNAMIC_CPUID_TSC_COMPENSATION {
        compensate_cpuid_tsc(vmx);
    }

    let sub_leaf = guest_registers.rcx as u32;

    // Execute CPUID instruction on the host and retrieve the result
    let mut cpuid_result = cpuid!(leaf, sub_leaf);

    log::trace!("Before modification: CPUID Leaf: {:#x}, EAX: {:#x}, EBX: {:#x}, ECX: {:#x}, EDX: {:#x}", leaf, cpuid_result.eax, cpuid_result.ebx, cpuid_result.ecx, cpuid_result.edx);

    mask_cpuid_result(leaf, sub_leaf, &mut cpuid_result);

    log::trace!("After modification: CPUID Leaf: {:#x}, EAX: {:#x}, EBX: {:#x}, ECX: {:#x}, EDX: {:#x}", leaf, cpuid_result.eax, cpuid_result.ebx, cpuid_result.ecx, cpuid_result.edx);

    // Update the guest registers
    guest_registers.rax = cpuid_result.eax as u64;
    guest_registers.rbx = cpuid_result.ebx as u64;
    guest_registers.rcx = cpuid_result.ecx as u64;
    guest_registers.rdx = cpuid_result.edx as u64;

    log::trace!("CPUID VMEXIT handled successfully!");

    ExitType::IncrementRIP
}

fn mask_cpuid_result(leaf: u32, sub_leaf: u32, cpuid_result: &mut CpuIdResult) {
    match leaf {
        // Handle CPUID for standard feature information.
        leaf if leaf == CpuidLeaf::FeatureInformation as u32 => {
            log::trace!("CPUID leaf 1 detected (Standard Feature Information).");
            // Hide hypervisor presence by setting the appropriate bit in ECX.
            cpuid_result
                .ecx
                .set_bit(FeatureBits::HypervisorPresentBit as usize, false);

            // Hide VMX support by setting the appropriate bit in ECX.
            cpuid_result
                .ecx
                .set_bit(FeatureBits::HypervisorVmxSupportBit as usize, false);

            cpuid_result
                .ecx
                .set_bit(FeatureBits::SaferModeExtensionsBit as usize, false);
        }
        // Keep hidden control leaves zeroed unless they were authenticated and
        // handled before reaching this masking path.
        0x4000_0000..=0x4000_00ff => {
            log::trace!("CPUID leaf {:#x} hidden.", leaf);
            *cpuid_result = CpuIdResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            };
        }
        leaf if leaf == CpuidLeaf::ExtendedFeatureInformation as u32 && sub_leaf == 0 => {
            log::trace!("CPUID leaf 7 detected (Extended Feature Information).");
            cpuid_result.ebx.set_bit(2, false);
            cpuid_result.ebx.set_bit(25, false);
            cpuid_result.ecx.set_bit(5, false);
            cpuid_result.ecx.set_bit(30, false);
        }
        leaf if leaf == CpuidLeaf::SgxCapabilities as u32 => {
            log::trace!("CPUID leaf 0x12 detected (SGX Capabilities).");
            *cpuid_result = CpuIdResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            };
        }
        _ => { /* Pass through other CPUID leaves unchanged. */ }
    }
}

fn cpuid_comm_authorized(guest_registers: &GuestRegisters) -> bool {
    guest_registers.r10 == VMCALL_MAGIC && guest_registers.r11 == VMCALL_MAGIC
}

fn next_tsc_offset(current: u64, compensation_cycles: u64) -> u64 {
    let current_compensation = if current & (1 << 63) != 0 {
        0u64.wrapping_sub(current)
    } else {
        0
    };
    let next_compensation = current_compensation
        .saturating_add(compensation_cycles)
        .min(MAX_CPUID_TSC_COMPENSATION_CYCLES);

    0u64.wrapping_sub(next_compensation)
}

fn compensate_cpuid_tsc(vmx: &mut Vmx) {
    vmx.tsc_offset = next_tsc_offset(vmx.tsc_offset, CPUID_TSC_COMPENSATION_CYCLES);
    crate::intel::diag::TSC_OFFSET.store(vmx.tsc_offset, core::sync::atomic::Ordering::Relaxed);

    if let Err(error) = vmwrite_checked(vmcs::control::TSC_OFFSET_FULL, vmx.tsc_offset) {
        log::error!("Failed to update TSC offset after CPUID exit: {:?}", error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x86::cpuid::CpuIdResult;

    #[test]
    fn feature_leaf_hides_hypervisor_and_vmx_bits() {
        let mut result = CpuIdResult {
            eax: 0,
            ebx: 0,
            ecx: (1 << FeatureBits::HypervisorPresentBit as u32)
                | (1 << FeatureBits::HypervisorVmxSupportBit as u32)
                | (1 << FeatureBits::SaferModeExtensionsBit as u32),
            edx: 0,
        };

        mask_cpuid_result(CpuidLeaf::FeatureInformation as u32, 0, &mut result);

        assert_eq!(
            result.ecx & (1 << FeatureBits::HypervisorPresentBit as u32),
            0
        );
        assert_eq!(
            result.ecx & (1 << FeatureBits::HypervisorVmxSupportBit as u32),
            0
        );
        assert_eq!(
            result.ecx & (1 << FeatureBits::SaferModeExtensionsBit as u32),
            0
        );
    }

    #[test]
    fn extended_feature_leaf_hides_sgx_and_intel_pt_bits() {
        let mut result = CpuIdResult {
            eax: 0,
            ebx: (1 << 2) | (1 << 25),
            ecx: (1 << 5) | (1 << 30),
            edx: 0,
        };

        mask_cpuid_result(CpuidLeaf::ExtendedFeatureInformation as u32, 0, &mut result);

        assert_eq!(result.ebx & (1 << 2), 0);
        assert_eq!(result.ebx & (1 << 25), 0);
        assert_eq!(result.ecx & (1 << 5), 0);
        assert_eq!(result.ecx & (1 << 30), 0);
    }

    #[test]
    fn extended_feature_subleafs_other_than_zero_are_not_sgx_masked() {
        let mut result = CpuIdResult {
            eax: 0,
            ebx: 1 << 2,
            ecx: 1 << 30,
            edx: 0,
        };

        mask_cpuid_result(CpuidLeaf::ExtendedFeatureInformation as u32, 1, &mut result);

        assert_eq!(result.ebx & (1 << 2), 1 << 2);
        assert_eq!(result.ecx & (1 << 30), 1 << 30);
    }

    #[test]
    fn sgx_capability_leaf_is_zeroed() {
        let mut result = CpuIdResult {
            eax: 1,
            ebx: 2,
            ecx: 3,
            edx: 4,
        };

        mask_cpuid_result(CpuidLeaf::SgxCapabilities as u32, 0, &mut result);

        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, 0);
    }

    #[test]
    fn hypervisor_leaves_are_zeroed() {
        let mut result = CpuIdResult {
            eax: 0x4000_0010,
            ebx: 0x7263_694d,
            ecx: 0x666f_736f,
            edx: 0x7648_2074,
        };

        mask_cpuid_result(CpuidLeaf::HypervisorVendor as u32, 0, &mut result);

        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, 0);
    }

    #[test]
    fn unauthenticated_communication_leaf_is_zeroed() {
        let mut result = CpuIdResult {
            eax: 0x1234,
            ebx: 0x5678,
            ecx: 0x9abc,
            edx: 0xdef0,
        };

        mask_cpuid_result(CPUID_COMM_LEAF, 0, &mut result);

        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, 0);
    }

    #[test]
    fn cpuid_communication_leaf_lives_in_hidden_hypervisor_range() {
        assert!((0x4000_0000..=0x4000_00ff).contains(&CPUID_COMM_LEAF));
    }

    #[test]
    fn cpuid_communication_requires_dual_auth_token() {
        let mut regs = GuestRegisters::default();
        assert!(!cpuid_comm_authorized(&regs));

        regs.r10 = VMCALL_MAGIC;
        assert!(!cpuid_comm_authorized(&regs));

        regs.r11 = VMCALL_MAGIC;
        assert!(cpuid_comm_authorized(&regs));
    }

    #[test]
    fn cpuid_tsc_compensation_accumulates_negative_offset() {
        assert_eq!(next_tsc_offset(0, 600), u64::MAX - 599);
        assert_eq!(next_tsc_offset(u64::MAX - 599, 600), u64::MAX - 1199);
    }

    #[test]
    fn cpuid_tsc_compensation_is_capped_to_avoid_clock_drift() {
        let capped_offset = 0u64.wrapping_sub(MAX_CPUID_TSC_COMPENSATION_CYCLES);

        assert_eq!(
            next_tsc_offset(capped_offset, CPUID_TSC_COMPENSATION_CYCLES),
            capped_offset
        );
    }

    #[test]
    fn dynamic_cpuid_tsc_compensation_is_disabled_by_default() {
        assert!(!ENABLE_DYNAMIC_CPUID_TSC_COMPENSATION);
    }
}
