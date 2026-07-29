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
    core::sync::atomic::{AtomicU64, Ordering},
    x86::{
        cpuid::{cpuid, CpuIdResult},
        time::rdtsc,
        vmx::vmcs,
    },
};

fn minimal_cpuid() -> bool {
    option_env!("HV_MINIMAL").map_or(false, |v| v == "1")
}

pub const CPUID_BARE_METAL_COST_DEFAULT: u64 = 120;
// VM-exit transition: guest CPUID → CPU saves state → loads host → our handler rdtsc().
// Subtract this from cpuid_entry_tsc to approximate the guest-side TSC at CPUID time.
// Kept conservative and only used by the explicitly gated timing path.
pub const VMEXIT_ENTRY_OVERHEAD: u64 = 600;

static CPUID_BARE_METAL_COST: AtomicU64 = AtomicU64::new(0);

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

    /// Intel Processor Trace capability leaf.
    ProcessorTraceCapabilities = 0x14,

    /// Architectural Last Branch Record capability leaf.
    ArchitecturalLbrCapabilities = 0x1C,
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

    if leaf == CPUID_COMM_LEAF {
        if cpuid_comm_authorized(guest_registers) {
            return dispatch_command(guest_registers, vmx);
        }
        // Keep the diagnostic leaf architecturally absent unless both
        // channel tokens are present. Do this before any host CPUID path so
        // the four guest-visible result registers are always zero.
        write_cpuid_result(guest_registers, zero_cpuid_result());
        return ExitType::IncrementRIP;
    }

    let sub_leaf = guest_registers.rcx as u32;
    let r = guest_cpuid_result(leaf, sub_leaf, |l, s| cpuid!(l, s));
    write_cpuid_result(guest_registers, r);

    // Ophion CPUID→RDTSC spoofing (2026-07-16 EXPERIMENT: disabled).
    //
    // Ophion spoofs the NEXT RDTSC after a CPUID to make (rdtsc_after -
    // rdtsc_before) look like bare-metal CPUID cost (~120 cycles). Problem:
    // APERF/MPERF are NOT spoofed and cannot be cheaply intercepted (~1M
    // reads/s per CPU crashes the box). Anti-cheat measuring APERF/TSC ratio
    // over a CPUID sees: TSC-delta ≈ 120 (spoofed), APERF-delta ≈ 700 (raw
    // includes ~600-cycle VM-exit overhead) → ratio ~6x, way above normal
    // turbo (~1.5x). This inconsistency IS a detection vector.
    //
    // Trade-off: with Ophion OFF, CPUID looks "slow" (bare-metal ~120 →
    // observed ~2000). But TSC/APERF/MPERF all agree (all include the
    // stolen cycles equally). A single, honest leak beats two mutually-
    // inconsistent leaks. VMEXIT_ENTRY_OVERHEAD remains conservative; the
    // bare-metal CPUID cost is calibrated once on the current host instead of
    // using the old fixed 120-cycle value.
    //
    // Set HV_ENABLE_OPHION=1 at build time to re-arm the trap for A/B tests.
    if !minimal_cpuid() && ophion_enabled() {
        let _ = cpuid_bare_metal_cost();
        vmx.cpuid_entry_tsc = exit_tsc_start;
        enable_rdtsc_exiting();
    }

    ExitType::IncrementRIP
}

pub fn cpuid_bare_metal_cost() -> u64 {
    let cached = CPUID_BARE_METAL_COST.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }

    let mut best = u64::MAX;
    let mut i = 0;
    while i < 16 {
        let start = unsafe { rdtsc() };
        let _ = cpuid!(0, 0);
        let elapsed = unsafe { rdtsc() }.wrapping_sub(start);
        if elapsed < best {
            best = elapsed;
        }
        i += 1;
    }
    let measured = if best == u64::MAX {
        CPUID_BARE_METAL_COST_DEFAULT
    } else {
        best.clamp(50, 300)
    };
    let _ = CPUID_BARE_METAL_COST.compare_exchange(0, measured, Ordering::Release, Ordering::Relaxed);
    CPUID_BARE_METAL_COST.load(Ordering::Acquire)
}

fn ophion_enabled() -> bool {
    option_env!("HV_ENABLE_OPHION").map_or(false, |v| v == "1")
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

const TRANSPARENT_MODE: bool = transparent_mode_enabled(option_env!("HV_TRANSPARENT"));

pub(super) const fn transparent_mode_enabled(value: Option<&str>) -> bool {
    matches!(value, Some(v) if v.as_bytes().len() == 1 && v.as_bytes()[0] == b'1')
}

fn guest_cpuid_result(
    leaf: u32,
    sub_leaf: u32,
    mut host_cpuid: impl FnMut(u32, u32) -> CpuIdResult,
) -> CpuIdResult {
    // Hypervisor leaves are never a hardware feature-discovery surface.
    // Keep them zero even in transparent diagnostic builds; the only
    // diagnostic entry point is handled separately by handle_cpuid after
    // dual-token authorization.
    if cpuid_leaf_is_zeroed_without_host(leaf) {
        return zero_cpuid_result();
    }

    if TRANSPARENT_MODE {
        // Diagnostic mode: return native hardware leaves without feature
        // masking. Hypervisor/capability leaves were excluded above.
        return host_cpuid(leaf, sub_leaf);
    }

    let mut cpuid_result = host_cpuid(leaf, sub_leaf);
    mask_cpuid_result(leaf, sub_leaf, &mut cpuid_result);
    cpuid_result
}

fn cpuid_leaf_is_zeroed_without_host(leaf: u32) -> bool {
    matches!(leaf, 0x4000_0000..=0x4fff_ffff)
        || leaf == CpuidLeaf::SgxCapabilities as u32
        || leaf == CpuidLeaf::ProcessorTraceCapabilities as u32
        || leaf == CpuidLeaf::ArchitecturalLbrCapabilities as u32
}

const fn zero_cpuid_result() -> CpuIdResult {
    CpuIdResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    }
}

#[inline]
fn write_cpuid_result(guest_registers: &mut GuestRegisters, result: CpuIdResult) {
    guest_registers.rax = result.eax as u64;
    guest_registers.rbx = result.ebx as u64;
    guest_registers.rcx = result.ecx as u64;
    guest_registers.rdx = result.edx as u64;
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
            cpuid_result.edx.set_bit(19, false);
        }
        leaf
            if leaf == CpuidLeaf::SgxCapabilities as u32
                || leaf == CpuidLeaf::ProcessorTraceCapabilities as u32
                || leaf == CpuidLeaf::ArchitecturalLbrCapabilities as u32 =>
        {
            log::trace!("CPUID capability leaf {:#x} hidden.", leaf);
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
    fn extended_feature_leaf_hides_sgx_intel_pt_and_arch_lbr_bits() {
        let mut result = CpuIdResult {
            eax: 0,
            ebx: (1 << 2) | (1 << 25),
            ecx: (1 << 5) | (1 << 30),
            edx: 1 << 19,
        };

        mask_cpuid_result(CpuidLeaf::ExtendedFeatureInformation as u32, 0, &mut result);

        assert_eq!(result.ebx & (1 << 2), 0);
        assert_eq!(result.ebx & (1 << 25), 0);
        assert_eq!(result.ecx & (1 << 5), 0);
        assert_eq!(result.ecx & (1 << 30), 0);
        assert_eq!(result.edx & (1 << 19), 0);
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
    fn processor_trace_capability_leaf_is_zeroed() {
        let mut result = CpuIdResult {
            eax: 1,
            ebx: 2,
            ecx: 3,
            edx: 4,
        };

        mask_cpuid_result(
            CpuidLeaf::ProcessorTraceCapabilities as u32,
            0,
            &mut result,
        );

        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, 0);
    }

    #[test]
    fn architectural_lbr_capability_leaf_is_zeroed() {
        let result = guest_cpuid_result(
            CpuidLeaf::ArchitecturalLbrCapabilities as u32,
            0,
            |_, _| panic!("hidden architectural LBR leaf must not execute host cpuid"),
        );

        assert_eq!(result, zero_cpuid_result());
    }

    #[test]
    fn cpuid_result_writer_clears_all_guest_registers() {
        let mut regs = GuestRegisters {
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            ..GuestRegisters::default()
        };

        write_cpuid_result(&mut regs, zero_cpuid_result());

        assert_eq!((regs.rax, regs.rbx, regs.rcx, regs.rdx), (0, 0, 0, 0));
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
        assert!(cpuid_bare_metal_cost() >= 50 && cpuid_bare_metal_cost() <= 300);
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
    fn hidden_processor_trace_leaf_bypasses_host_cpuid() {
        let result = guest_cpuid_result(
            CpuidLeaf::ProcessorTraceCapabilities as u32,
            0,
            |_, _| panic!("hidden Intel PT leaf must not execute host cpuid"),
        );

        assert_eq!(result.eax, 0);
        assert_eq!(result.ebx, 0);
        assert_eq!(result.ecx, 0);
        assert_eq!(result.edx, 0);
    }

    #[test]
    fn transparent_mode_requires_explicit_one() {
        assert!(transparent_mode_enabled(Some("1")));
        assert!(!transparent_mode_enabled(None));
        assert!(!transparent_mode_enabled(Some("0")));
        assert!(!transparent_mode_enabled(Some("true")));
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
    fn leaf7_subleaf0_is_queried_per_logical_cpu_and_masked() {
        use core::cell::Cell;

        let calls = Cell::new(0);
        let host = |_, _| {
            calls.set(calls.get() + 1);
            CpuIdResult {
                eax: calls.get(),
                ebx: (1 << 2) | (1 << 25) | 0x40,
                ecx: (1 << 5) | (1 << 30) | 0x80,
                edx: (1 << 19) | 0x55aa,
            }
        };

        let first = guest_cpuid_result(CpuidLeaf::ExtendedFeatureInformation as u32, 0, host);
        let second = guest_cpuid_result(CpuidLeaf::ExtendedFeatureInformation as u32, 0, host);

        assert_eq!(calls.get(), 2);
        assert_ne!(first.eax, second.eax);
        assert_eq!(first.ebx & (1 << 2), 0);
        assert_eq!(first.ebx & (1 << 25), 0);
        assert_eq!(first.ecx & (1 << 5), 0);
        assert_eq!(first.ecx & (1 << 30), 0);
        assert_eq!(first.edx & (1 << 19), 0);
        assert_eq!(second.edx & (1 << 19), 0);
    }
}
