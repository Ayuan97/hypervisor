//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 4.10.4 Invalidation of TLBs and Paging-Structure Caches
//!
//! The INVVPID (Invalidate VPID) instruction is used to invalidate entries in the TLB and paging-structure caches
//! that are associated with a specific Virtual Processor Identifier (VPID). This is essential in virtualization
//! environments to maintain consistency of memory translations across different virtual processors.

use crate::error::HypervisorError;
use x86::msr;

pub const VPID_TAG: u16 = 0x1;

const EPT_VPID_CAP_INVVPID: u64 = 1 << 32;
const EPT_VPID_CAP_INDIVIDUAL_ADDRESS_INVVPID: u64 = 1 << 40;
const EPT_VPID_CAP_SINGLE_CONTEXT_INVVPID: u64 = 1 << 41;
const EPT_VPID_CAP_ALL_CONTEXT_INVVPID: u64 = 1 << 42;
const EPT_VPID_CAP_SINGLE_CONTEXT_RETAINING_GLOBALS_INVVPID: u64 = 1 << 43;

/// Represents the types of INVVPID operations.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InvvpidType {
    /// Invalidate mappings associated with a specific linear address and VPID.
    /// This type invalidates mappings—except global translations—associated with the specified VPID
    /// that would be used to translate the specified linear address.
    IndividualAddress = 0,

    /// Invalidate mappings associated with a specific VPID.
    /// This type invalidates all mappings—except global translations—associated with the specified VPID.
    SingleContext = 1,

    /// Invalidate mappings—including global translations—associated with all VPIDs.
    /// This type invalidates all mappings for all VPIDs.
    AllContexts = 2,

    /// Invalidate mappings associated with a specific VPID except global translations.
    /// This type uses the VPID in the descriptor and retains global translations.
    SingleContextRetainingGlobals = 3,
}

/// Represents an INVVPID descriptor.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvvpidDescriptor {
    /// Virtual Processor Identifier
    pub vpid: u16,
    /// Reserved fields (must be zero)
    pub reserved: [u16; 3],
    /// Linear address (used only for IndividualAddress type)
    pub linear_address: u64,
}

/// Performs the INVVPID instruction.
///
/// # Arguments
/// * `invvpid_type` - The type of invalidation to perform.
/// * `descriptor` - The INVVPID descriptor.
fn invvpid(invvpid_type: InvvpidType, descriptor: &InvvpidDescriptor) {
    let descriptor_ptr = descriptor as *const _ as u64;
    unsafe {
        core::arch::asm!(
        "invvpid {0}, [{1}]",
        in(reg) invvpid_type as u64,
        in(reg) descriptor_ptr,
        options(nostack)
        );
    }
}

/// Invalidates TLB and paging-structure cache entries associated with a specific linear address and VPID.
///
/// # Arguments
/// * `vpid` - Virtual Processor Identifier.
/// * `linear_address` - Specific linear address whose mappings are to be invalidated.
pub fn invvpid_individual_address(vpid: u16, linear_address: u64) {
    if let Err(error) = try_invvpid_individual_address(vpid, linear_address) {
        log::error!("Skipping individual-address INVVPID: {:?}", error);
    }
}

/// Invalidates TLB and paging-structure cache entries associated with a specific VPID.
///
/// # Arguments
/// * `vpid` - Virtual Processor Identifier.
pub fn invvpid_single_context(vpid: u16) {
    // Perform the INVVPID operation for a single context.
    if let Err(error) = try_invvpid_single_context(vpid) {
        log::error!("Skipping single-context INVVPID: {:?}", error);
    }
}

/// Invalidates TLB and paging-structure cache entries for all VPIDs.
///
/// This operation ignores the descriptor fields as they are irrelevant for the AllContexts type.
pub fn invvpid_all_contexts() {
    if let Err(error) = try_invvpid_all_contexts() {
        log::error!("Skipping all-context INVVPID: {:?}", error);
    }
}

pub fn try_invvpid_single_context(vpid: u16) -> Result<(), HypervisorError> {
    let cap = ept_vpid_capability();
    if !single_context_invvpid_supported(cap) {
        return Err(HypervisorError::VMXUnsupported);
    }

    let descriptor = InvvpidDescriptor {
        vpid,
        reserved: [0; 3],
        linear_address: 0,
    };
    invvpid(InvvpidType::SingleContext, &descriptor);
    Ok(())
}

pub fn try_invvpid_individual_address(
    vpid: u16,
    linear_address: u64,
) -> Result<(), HypervisorError> {
    let cap = ept_vpid_capability();
    if !individual_address_invvpid_supported(cap) {
        return Err(HypervisorError::VMXUnsupported);
    }

    let descriptor = InvvpidDescriptor {
        vpid,
        reserved: [0; 3],
        linear_address,
    };
    invvpid(InvvpidType::IndividualAddress, &descriptor);
    Ok(())
}

pub fn try_invvpid_single_context_retaining_globals(vpid: u16) -> Result<(), HypervisorError> {
    let cap = ept_vpid_capability();
    if !single_context_retaining_globals_invvpid_supported(cap) {
        return Err(HypervisorError::VMXUnsupported);
    }

    let descriptor = InvvpidDescriptor {
        vpid,
        reserved: [0; 3],
        linear_address: 0,
    };
    invvpid(InvvpidType::SingleContextRetainingGlobals, &descriptor);
    Ok(())
}

pub fn try_invvpid_all_contexts() -> Result<(), HypervisorError> {
    let cap = ept_vpid_capability();
    if !all_context_invvpid_supported(cap) {
        return Err(HypervisorError::VMXUnsupported);
    }

    let descriptor = InvvpidDescriptor {
        vpid: 0,           // Irrelevant for AllContexts
        reserved: [0; 3],  // Reserved fields, must be zero
        linear_address: 0, // Irrelevant for AllContexts
    };
    // Perform the INVVPID operation for all contexts.
    invvpid(InvvpidType::AllContexts, &descriptor);
    Ok(())
}

fn ept_vpid_capability() -> u64 {
    unsafe { msr::rdmsr(msr::IA32_VMX_EPT_VPID_CAP) }
}

fn single_context_invvpid_supported(capability: u64) -> bool {
    capability & (EPT_VPID_CAP_INVVPID | EPT_VPID_CAP_SINGLE_CONTEXT_INVVPID)
        == (EPT_VPID_CAP_INVVPID | EPT_VPID_CAP_SINGLE_CONTEXT_INVVPID)
}

fn individual_address_invvpid_supported(capability: u64) -> bool {
    capability & (EPT_VPID_CAP_INVVPID | EPT_VPID_CAP_INDIVIDUAL_ADDRESS_INVVPID)
        == (EPT_VPID_CAP_INVVPID | EPT_VPID_CAP_INDIVIDUAL_ADDRESS_INVVPID)
}

fn all_context_invvpid_supported(capability: u64) -> bool {
    capability & (EPT_VPID_CAP_INVVPID | EPT_VPID_CAP_ALL_CONTEXT_INVVPID)
        == (EPT_VPID_CAP_INVVPID | EPT_VPID_CAP_ALL_CONTEXT_INVVPID)
}

fn single_context_retaining_globals_invvpid_supported(capability: u64) -> bool {
    capability & (EPT_VPID_CAP_INVVPID | EPT_VPID_CAP_SINGLE_CONTEXT_RETAINING_GLOBALS_INVVPID)
        == (EPT_VPID_CAP_INVVPID | EPT_VPID_CAP_SINGLE_CONTEXT_RETAINING_GLOBALS_INVVPID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_context_invvpid_requires_instruction_and_type_capability_bits() {
        let invvpid = 1u64 << 32;
        let all_context = 1u64 << 42;

        assert!(!all_context_invvpid_supported(0));
        assert!(!all_context_invvpid_supported(invvpid));
        assert!(all_context_invvpid_supported(invvpid | all_context));
    }

    #[test]
    fn single_context_invvpid_requires_instruction_and_type_capability_bits() {
        let invvpid = 1u64 << 32;
        let single_context = 1u64 << 41;

        assert!(!single_context_invvpid_supported(0));
        assert!(!single_context_invvpid_supported(invvpid));
        assert!(single_context_invvpid_supported(invvpid | single_context));
    }

    #[test]
    fn individual_address_invvpid_requires_instruction_and_type_capability_bits() {
        let invvpid = 1u64 << 32;
        let individual_address = 1u64 << 40;

        assert!(!individual_address_invvpid_supported(0));
        assert!(!individual_address_invvpid_supported(invvpid));
        assert!(individual_address_invvpid_supported(
            invvpid | individual_address
        ));
    }

    #[test]
    fn single_context_retaining_globals_invvpid_requires_instruction_and_type_capability_bits() {
        let invvpid = 1u64 << 32;
        let retaining_globals = 1u64 << 43;

        assert!(!single_context_retaining_globals_invvpid_supported(0));
        assert!(!single_context_retaining_globals_invvpid_supported(invvpid));
        assert!(single_context_retaining_globals_invvpid_supported(
            invvpid | retaining_globals
        ));
    }

    #[test]
    fn invvpid_type_encoding_matches_intel_sdm() {
        assert_eq!(InvvpidType::IndividualAddress as u64, 0);
        assert_eq!(InvvpidType::SingleContext as u64, 1);
        assert_eq!(InvvpidType::AllContexts as u64, 2);
        assert_eq!(InvvpidType::SingleContextRetainingGlobals as u64, 3);
    }
}
