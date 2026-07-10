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
    core::sync::atomic::{AtomicBool, AtomicU64, Ordering},
    x86::{
        cpuid::{cpuid, CpuIdResult},
        vmx::vmcs,
    },
};

fn minimal_cpuid() -> bool {
    option_env!("HV_MINIMAL").map_or(false, |v| v == "1")
}

pub const CPUID_BARE_METAL_COST: u64 = 120;
// VM-exit transition: guest CPUID → CPU saves state → loads host → our handler rdtsc().
// Subtract this from cpuid_entry_tsc to approximate the guest-side TSC at CPUID time.
pub const VMEXIT_ENTRY_OVERHEAD: u64 = 600;

static LEAF7_SUBLEAF0_LOW: AtomicU64 = AtomicU64::new(0);
static LEAF7_SUBLEAF0_HIGH: AtomicU64 = AtomicU64::new(0);
static LEAF7_SUBLEAF0_READY: AtomicBool = AtomicBool::new(false);

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
pub fn handle_cpuid(guest_registers: &mut GuestRegisters, vmx: &mut Vmx, exit_tsc_start: u64) -> ExitType {
    let leaf = guest_registers.rax as u32;

    if leaf == CPUID_COMM_LEAF && cpuid_comm_authorized(guest_registers) {
        return dispatch_command(guest_registers, vmx);
    }

    let sub_leaf = guest_registers.rcx as u32;
    let r = guest_cpuid_result(leaf, sub_leaf, |l, s| cpuid!(l, s));
    guest_registers.rax = r.eax as u64;
    guest_registers.rbx = r.ebx as u64;
    guest_registers.rcx = r.ecx as u64;
    guest_registers.rdx = r.edx as u64;

    // Record high-CR8 CPUIDs to CMOS purely as a diagnostic breadcrumb —
    // don't act on them. Auto-devirtualizing at CR8 >= 15 seemed like a
    // way to let a mid-flight bugcheck finish (see 22:14:46 session where
    // it did produce a proper BSOD 0x139), but the follow-up run went
    // straight to black-screen restart after ~46 s of gameplay: yanking
    // a CPU out of VMX-root while Windows is at HIGH_LEVEL destabilises
    // something we can't diagnose from here. Rolled back to record-only.
    let cr8: u64;
    unsafe { core::arch::asm!("mov {}, cr8", out(reg) cr8, options(nomem, nostack)); }
    if cr8 >= 13 {
        // Write CR8 value to CMOS as diagnostic marker (survives hard reset).
        unsafe {
            core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") 0x72u8, options(nomem, nostack));
            core::arch::asm!("out dx, al", in("dx") 0x71u16, in("al") 0xBCu8, options(nomem, nostack));
            core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") 0x73u8, options(nomem, nostack));
            core::arch::asm!("out dx, al", in("dx") 0x71u16, in("al") cr8 as u8, options(nomem, nostack));
            // Write leaf to CMOS 0x74-0x75
            core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") 0x74u8, options(nomem, nostack));
            core::arch::asm!("out dx, al", in("dx") 0x71u16, in("al") leaf as u8, options(nomem, nostack));
            core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") 0x75u8, options(nomem, nostack));
            core::arch::asm!("out dx, al", in("dx") 0x71u16, in("al") (leaf >> 8) as u8, options(nomem, nostack));
        }
    }

    if !minimal_cpuid() {
        vmx.cpuid_entry_tsc = exit_tsc_start;
        enable_rdtsc_exiting();
    }

    ExitType::IncrementRIP
}

fn enable_rdtsc_exiting() {
    if let Ok(val) =
        crate::intel::support::vmread_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS)
    {
        let new_val = val | (1 << 12); // bit 12 = RDTSC exiting
        let _ = vmwrite_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, new_val);
    }
}

pub fn disable_rdtsc_exiting() {
    if let Ok(val) =
        crate::intel::support::vmread_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS)
    {
        let new_val = val & !(1 << 12);
        let _ = vmwrite_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, new_val);
    }
}

const TRANSPARENT_MODE: bool = option_env!("HV_TRANSPARENT").is_some();

fn guest_cpuid_result(
    leaf: u32,
    sub_leaf: u32,
    mut host_cpuid: impl FnMut(u32, u32) -> CpuIdResult,
) -> CpuIdResult {
    if TRANSPARENT_MODE {
        // Diagnostic mode: return native CPUID, no masking at all.
        // Hidden comm leaf still returns zeros (it's our channel, not hiding).
        if leaf == CPUID_COMM_LEAF {
            return zero_cpuid_result();
        }
        return host_cpuid(leaf, sub_leaf);
    }

    if cpuid_leaf_is_zeroed_without_host(leaf) {
        return zero_cpuid_result();
    }

    if leaf == CpuidLeaf::ExtendedFeatureInformation as u32 && sub_leaf == 0 {
        return cached_leaf7_subleaf0(&mut host_cpuid);
    }

    let mut cpuid_result = host_cpuid(leaf, sub_leaf);
    mask_cpuid_result(leaf, sub_leaf, &mut cpuid_result);
    cpuid_result
}

fn cached_leaf7_subleaf0(host_cpuid: &mut impl FnMut(u32, u32) -> CpuIdResult) -> CpuIdResult {
    if LEAF7_SUBLEAF0_READY.load(Ordering::Acquire) {
        return unpack_cpuid_result(
            LEAF7_SUBLEAF0_LOW.load(Ordering::Relaxed),
            LEAF7_SUBLEAF0_HIGH.load(Ordering::Relaxed),
        );
    }

    let mut cpuid_result = host_cpuid(CpuidLeaf::ExtendedFeatureInformation as u32, 0);
    mask_cpuid_result(
        CpuidLeaf::ExtendedFeatureInformation as u32,
        0,
        &mut cpuid_result,
    );
    let (low, high) = pack_cpuid_result(cpuid_result);
    LEAF7_SUBLEAF0_LOW.store(low, Ordering::Relaxed);
    LEAF7_SUBLEAF0_HIGH.store(high, Ordering::Relaxed);
    LEAF7_SUBLEAF0_READY.store(true, Ordering::Release);
    cpuid_result
}

fn cpuid_leaf_is_zeroed_without_host(leaf: u32) -> bool {
    matches!(leaf, 0x4000_0000..=0x4fff_ffff) || leaf == CpuidLeaf::SgxCapabilities as u32
}

const fn zero_cpuid_result() -> CpuIdResult {
    CpuIdResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    }
}

const fn pack_cpuid_result(result: CpuIdResult) -> (u64, u64) {
    (
        result.eax as u64 | ((result.ebx as u64) << 32),
        result.ecx as u64 | ((result.edx as u64) << 32),
    )
}

const fn unpack_cpuid_result(low: u64, high: u64) -> CpuIdResult {
    CpuIdResult {
        eax: low as u32,
        ebx: (low >> 32) as u32,
        ecx: high as u32,
        edx: (high >> 32) as u32,
    }
}

#[cfg(test)]
fn reset_cpuid_cache_for_test() {
    LEAF7_SUBLEAF0_LOW.store(0, Ordering::Relaxed);
    LEAF7_SUBLEAF0_HIGH.store(0, Ordering::Relaxed);
    LEAF7_SUBLEAF0_READY.store(false, Ordering::Relaxed);
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
        // Keep hidden hypervisor leaves zeroed unless they were authenticated and
        // handled before reaching this masking path.
        0x4000_0000..=0x4fff_ffff => {
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
    fn cpuid_bare_metal_cost_is_reasonable() {
        assert!(CPUID_BARE_METAL_COST >= 50 && CPUID_BARE_METAL_COST <= 300);
    }

    #[test]
    fn hidden_hypervisor_leaf_bypasses_host_cpuid() {
        let result = guest_cpuid_result(CPUID_COMM_LEAF, 0, |_, _| {
            panic!("hidden leaf must not execute host cpuid")
        });

        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, 0);
    }

    #[test]
    fn extended_hypervisor_leaf_range_bypasses_host_cpuid() {
        let result = guest_cpuid_result(0x4000_0100, 0, |_, _| {
            panic!("extended hypervisor leaf must not execute host cpuid")
        });

        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, 0);
    }

    #[test]
    fn leaf7_subleaf0_uses_masked_cache() {
        use core::cell::Cell;

        reset_cpuid_cache_for_test();
        let calls = Cell::new(0);
        let host = |_, _| {
            calls.set(calls.get() + 1);
            CpuIdResult {
                eax: 0x1234,
                ebx: (1 << 2) | (1 << 25) | 0x40,
                ecx: (1 << 5) | (1 << 30) | 0x80,
                edx: 0x55aa,
            }
        };

        let first = guest_cpuid_result(CpuidLeaf::ExtendedFeatureInformation as u32, 0, host);
        let second = guest_cpuid_result(CpuidLeaf::ExtendedFeatureInformation as u32, 0, host);

        assert_eq!(calls.get(), 1);
        assert_eq!(first, second);
        assert_eq!(first.ebx & (1 << 2), 0);
        assert_eq!(first.ebx & (1 << 25), 0);
        assert_eq!(first.ecx & (1 << 5), 0);
        assert_eq!(first.ecx & (1 << 30), 0);
    }
}
