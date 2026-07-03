//! A crate responsible for managing the VMCS region for VMX operations.
//!
//! This crate provides functionality to set up the VMCS region in memory, which
//! is vital for VMX operations on the CPU. It also offers utility functions for
//! adjusting VMCS entries and displaying VMCS state for debugging purposes.

use {
    // Internal crate usages
    crate::{
        error::HypervisorError,
        intel::{
            controls::{adjust_vmx_controls, VmxControl},
            descriptor::DescriptorTables,
            invept::try_invept_single_context,
            invvpid::{try_invvpid_single_context, VPID_TAG},
            segmentation::SegmentDescriptor,
            shared_data::SharedData,
            support::{vmclear, vmptrld, vmread, vmwrite_checked},
        },
        utils::capture::GuestRegisters,
        utils::{
            addresses::PhysicalAddress,
            alloc::{KernelAlloc, PhysicalAllocator},
            capture::CONTEXT,
            instructions::cr3,
        },
    },

    // External crate usages
    alloc::boxed::Box,
    bitfield::BitMut,
    core::fmt,
    x86::{
        controlregs,
        cpuid::cpuid,
        current::paging::BASE_PAGE_SIZE,
        dtables::{self},
        msr::{self},
        segmentation::SegmentSelector,
        task,
        vmx::vmcs::{self},
    },
    x86_64::registers::control::{Cr0, Cr4},
};

/// Represents the VMCS region in memory.
///
/// The VMCS region is essential for VMX operations on the CPU.
/// This structure offers methods for setting up the VMCS region, adjusting VMCS entries,
/// and performing related tasks.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
#[repr(C, align(4096))]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; BASE_PAGE_SIZE - 8],
}

impl Vmcs {
    /// Sets up the VMCS region.
    ///
    /// # Arguments
    /// * `vmcs_region` - A mutable reference to the VMCS region in memory.
    ///
    /// # Returns
    /// A result indicating success or an error.
    pub fn setup(vmcs_region: &mut Box<Vmcs, PhysicalAllocator>) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMCS region");

        let vmcs_region_physical_address =
            PhysicalAddress::pa_from_va(vmcs_region.as_ref() as *const _ as _);

        if vmcs_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::trace!("VMCS Region Virtual Address: {:p}", vmcs_region);
        log::trace!(
            "VMCS Region Physical Addresss: 0x{:x}",
            vmcs_region_physical_address
        );

        vmcs_region.revision_id = Self::get_vmcs_revision_id();
        vmcs_region.as_mut().revision_id.set_bit(31, false);

        // Clear the VMCS region.
        vmclear(vmcs_region_physical_address)?;
        log::trace!("VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(vmcs_region_physical_address)?;
        log::trace!("VMPTRLD successful!");

        log::trace!("VMCS setup successfully!");

        Ok(())
    }

    /// Initialize the guest state for the currently loaded VMCS.
    ///
    /// The method sets up various guest state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.4 GUEST-STATE AREA.
    ///
    /// # Arguments
    /// * `context` - Context containing the guest's register states.
    /// * `guest_descriptor_table` - Descriptor tables for the guest.
    /// * `guest_registers` - Guest registers for the guest.
    #[rustfmt::skip]
    pub fn setup_guest_registers_state(context: &CONTEXT, guest_descriptor_table: &Box<DescriptorTables, KernelAlloc>, guest_registers: &mut GuestRegisters) -> Result<(), HypervisorError> {
        log::debug!("Setting up Guest Registers State");

        vmwrite_checked(vmcs::guest::CR0, Cr0::read_raw())?;
        vmwrite_checked(vmcs::guest::CR3, cr3())?;
        vmwrite_checked(vmcs::guest::CR4, Cr4::read_raw())?;

        vmwrite_checked(vmcs::guest::DR7, context.Dr7)?;

        vmwrite_checked(vmcs::guest::RSP, context.Rsp)?;
        vmwrite_checked(vmcs::guest::RIP, context.Rip)?;
        vmwrite_checked(vmcs::guest::RFLAGS, context.EFlags)?;

        vmwrite_checked(vmcs::guest::CS_SELECTOR, context.SegCs)?;
        vmwrite_checked(vmcs::guest::SS_SELECTOR, context.SegSs)?;
        vmwrite_checked(vmcs::guest::DS_SELECTOR, context.SegDs)?;
        vmwrite_checked(vmcs::guest::ES_SELECTOR, context.SegEs)?;
        vmwrite_checked(vmcs::guest::FS_SELECTOR, context.SegFs)?;
        vmwrite_checked(vmcs::guest::GS_SELECTOR, context.SegGs)?;
        unsafe { vmwrite_checked(vmcs::guest::LDTR_SELECTOR, dtables::ldtr().bits() as u64)? };
        unsafe { vmwrite_checked(vmcs::guest::TR_SELECTOR, task::tr().bits() as u64)? };

        vmwrite_checked(vmcs::guest::CS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).base_address)?;
        vmwrite_checked(vmcs::guest::SS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).base_address)?;
        vmwrite_checked(vmcs::guest::DS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).base_address)?;
        vmwrite_checked(vmcs::guest::ES_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).base_address)?;
        unsafe { vmwrite_checked(vmcs::guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE))? };
        unsafe { vmwrite_checked(vmcs::guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE))? };
        unsafe { vmwrite_checked(vmcs::guest::LDTR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).base_address)? };
        unsafe { vmwrite_checked(vmcs::guest::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).base_address)? };

        vmwrite_checked(vmcs::guest::CS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).segment_limit)?;
        vmwrite_checked(vmcs::guest::SS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).segment_limit)?;
        vmwrite_checked(vmcs::guest::DS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).segment_limit)?;
        vmwrite_checked(vmcs::guest::ES_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).segment_limit)?;
        vmwrite_checked(vmcs::guest::FS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegFs), &guest_descriptor_table.gdtr).segment_limit)?;
        vmwrite_checked(vmcs::guest::GS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegGs), &guest_descriptor_table.gdtr).segment_limit)?;
        unsafe { vmwrite_checked(vmcs::guest::LDTR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).segment_limit)? };
        unsafe { vmwrite_checked(vmcs::guest::TR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).segment_limit)? };

        vmwrite_checked(vmcs::guest::CS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).access_rights.bits())?;
        vmwrite_checked(vmcs::guest::SS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).access_rights.bits())?;
        vmwrite_checked(vmcs::guest::DS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).access_rights.bits())?;
        vmwrite_checked(vmcs::guest::ES_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).access_rights.bits())?;
        vmwrite_checked(vmcs::guest::FS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegFs), &guest_descriptor_table.gdtr).access_rights.bits())?;
        vmwrite_checked(vmcs::guest::GS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegGs), &guest_descriptor_table.gdtr).access_rights.bits())?;
        unsafe { vmwrite_checked(vmcs::guest::LDTR_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).access_rights.bits())? };
        unsafe { vmwrite_checked(vmcs::guest::TR_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).access_rights.bits())? };

        vmwrite_checked(vmcs::guest::GDTR_BASE, guest_descriptor_table.gdtr.base as u64)?;
        vmwrite_checked(vmcs::guest::IDTR_BASE, guest_descriptor_table.idtr.base as u64)?;

        vmwrite_checked(vmcs::guest::GDTR_LIMIT, guest_descriptor_table.gdtr.limit as u64)?;
        vmwrite_checked(vmcs::guest::IDTR_LIMIT, guest_descriptor_table.idtr.limit as u64)?;

        unsafe {
            vmwrite_checked(vmcs::guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL))?;
            vmwrite_checked(vmcs::guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS))?;
            vmwrite_checked(vmcs::guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP))?;
            vmwrite_checked(vmcs::guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP))?;
            vmwrite_checked(vmcs::guest::LINK_PTR_FULL, u64::MAX)?;
        }

        let xmm_context = unsafe { context.Anonymous.Anonymous };

        // Note: VMCS does not manage all registers; some require manual intervention for saving and loading.
        // This includes general-purpose registers and xmm registers, which must be explicitly preserved and restored by the software.
        guest_registers.xmm0 = xmm_context.Xmm0;
        guest_registers.xmm1 = xmm_context.Xmm1;
        guest_registers.xmm2 = xmm_context.Xmm2;
        guest_registers.xmm3 = xmm_context.Xmm3;
        guest_registers.xmm4 = xmm_context.Xmm4;
        guest_registers.xmm5 = xmm_context.Xmm5;
        guest_registers.xmm6 = xmm_context.Xmm6;
        guest_registers.xmm7 = xmm_context.Xmm7;
        guest_registers.xmm8 = xmm_context.Xmm8;
        guest_registers.xmm9 = xmm_context.Xmm9;
        guest_registers.xmm10 = xmm_context.Xmm10;
        guest_registers.xmm11 = xmm_context.Xmm11;
        guest_registers.xmm12 = xmm_context.Xmm12;
        guest_registers.xmm13 = xmm_context.Xmm13;
        guest_registers.xmm14 = xmm_context.Xmm14;
        guest_registers.xmm15 = xmm_context.Xmm15;

        guest_registers.rax = context.Rax;
        guest_registers.rbx = context.Rbx;
        guest_registers.rcx = context.Rcx;
        guest_registers.rdx = context.Rdx;
        guest_registers.rdi = context.Rdi;
        guest_registers.rsi = context.Rsi;
        guest_registers.rbp = context.Rbp;
        guest_registers.r8 = context.R8;
        guest_registers.r9 = context.R9;
        guest_registers.r10 = context.R10;
        guest_registers.r11 = context.R11;
        guest_registers.r12 = context.R12;
        guest_registers.r13 = context.R13;
        guest_registers.r14 = context.R14;
        guest_registers.r15 = context.R15;

        log::debug!("Guest Registers State setup successfully!");
        Ok(())
    }

    /// Initialize the host state for the currently loaded VMCS.
    ///
    /// The method sets up various host state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.5 HOST-STATE AREA.
    ///
    /// # Arguments
    /// * `context` - Context containing the host's register states.
    /// * `host_descriptor_table` - Descriptor tables for the host.
    #[rustfmt::skip]
    pub fn setup_host_registers_state(context: &CONTEXT, host_descriptor_table: &Box<DescriptorTables, KernelAlloc>) -> Result<(), HypervisorError> {
        log::debug!("Setting up Host Registers State");

        unsafe { vmwrite_checked(vmcs::host::CR0, controlregs::cr0().bits() as u64)? };
        vmwrite_checked(vmcs::host::CR3, unsafe { crate::utils::nt::NTOSKRNL_CR3 })?;
        vmwrite_checked(vmcs::host::CR4, Cr4::read_raw())?;

        // The RIP/RSP registers are set within `launch_vm`.

        const SELECTOR_MASK: u16 = 0xF8;
        vmwrite_checked(vmcs::host::CS_SELECTOR, context.SegCs & SELECTOR_MASK)?;
        vmwrite_checked(vmcs::host::SS_SELECTOR, context.SegSs & SELECTOR_MASK)?;
        vmwrite_checked(vmcs::host::DS_SELECTOR, context.SegDs & SELECTOR_MASK)?;
        vmwrite_checked(vmcs::host::ES_SELECTOR, context.SegEs & SELECTOR_MASK)?;
        vmwrite_checked(vmcs::host::FS_SELECTOR, context.SegFs & SELECTOR_MASK)?;
        vmwrite_checked(vmcs::host::GS_SELECTOR, context.SegGs & SELECTOR_MASK)?;
        unsafe { vmwrite_checked(vmcs::host::TR_SELECTOR, task::tr().bits() & SELECTOR_MASK)? };

        unsafe { vmwrite_checked(vmcs::host::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE))? };
        unsafe { vmwrite_checked(vmcs::host::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE))? };
        unsafe { vmwrite_checked(vmcs::host::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &host_descriptor_table.gdtr).base_address)? };

        vmwrite_checked(vmcs::host::GDTR_BASE, host_descriptor_table.gdtr.base as u64)?;
        vmwrite_checked(vmcs::host::IDTR_BASE, host_descriptor_table.idtr.base as u64)?;

        unsafe {
            vmwrite_checked(vmcs::host::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS))?;
            vmwrite_checked(vmcs::host::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP))?;
            vmwrite_checked(vmcs::host::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP))?;
        }

        log::debug!("Host Registers State setup successfully!");

        Ok(())
    }

    /// Initialize the VMCS control values for the currently loaded VMCS.
    ///
    /// The method sets up various VMX control fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual sections:
    /// - 25.6 VM-EXECUTION CONTROL FIELDS
    /// - 25.7 VM-EXIT CONTROL FIELDS
    /// - 25.8 VM-ENTRY CONTROL FIELDS
    ///
    /// # Arguments
    /// * `shared_data` - Shared data between processors.
    #[rustfmt::skip]
    pub fn setup_vmcs_control_fields(shared_data: &mut SharedData) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMCS Control Fields");

        let primary_ctl = required_primary_controls();
        let secondary_ctl = required_secondary_controls();
        let requested_secondary_ctl = requested_secondary_controls();
        let entry_ctl = required_entry_controls();
        let requested_entry_ctl = requested_entry_controls();
        let exit_ctl = required_exit_controls();
        let requested_exit_ctl = requested_exit_controls();
        const PINBASED_CTL: u64 =
            vmcs::control::PinbasedControls::NMI_EXITING.bits() as u64;

        let ctl_pin = adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL)?;
        let ctl_pri = adjust_vmx_controls(VmxControl::ProcessorBased, primary_ctl)?;
        let ctl_sec = adjust_vmx_controls(VmxControl::ProcessorBased2, requested_secondary_ctl)?;
        let ctl_ent = adjust_vmx_controls(VmxControl::VmEntry, requested_entry_ctl)?;
        let ctl_ext = adjust_vmx_controls(VmxControl::VmExit, requested_exit_ctl)?;

        if !required_controls_present(primary_ctl, ctl_pri)
            || !required_controls_present(secondary_ctl, ctl_sec)
            || !required_controls_present(entry_ctl, ctl_ent)
            || !required_controls_present(exit_ctl, ctl_ext)
        {
            log::error!(
                "Required VMX controls unavailable: pri={:#x}/{:#x} sec={:#x}/{:#x} ent={:#x}/{:#x} ext={:#x}/{:#x}",
                ctl_pri,
                primary_ctl,
                ctl_sec,
                secondary_ctl,
                ctl_ent,
                entry_ctl,
                ctl_ext,
                exit_ctl
            );
            return Err(HypervisorError::VMXUnsupported);
        }

        if !pinbased_interrupt_exiting_ready(ctl_pin) {
            log::error!(
                "Unsupported pin-based VMX controls are active: pin={:#x}",
                ctl_pin
            );
            return Err(HypervisorError::VMXUnsupported);
        }
        let unsupported_primary = unsupported_primary_exit_controls(ctl_pri);
        if unsupported_primary != 0 {
            log::error!(
                "Unsupported primary VM-exit controls are active: pri={:#x} unsupported={:#x}",
                ctl_pri,
                unsupported_primary
            );
            return Err(HypervisorError::VMXUnsupported);
        }
        let unsupported_secondary = unsupported_secondary_controls(ctl_sec);
        if unsupported_secondary != 0 {
            log::error!(
                "Unsupported secondary VM-execution controls are active: sec={:#x} unsupported={:#x}",
                ctl_sec,
                unsupported_secondary
            );
            return Err(HypervisorError::VMXUnsupported);
        }
        let unsupported_entry = unsupported_entry_controls(ctl_ent);
        if unsupported_entry != 0 {
            log::error!(
                "Unsupported VM-entry controls are active: ent={:#x} unsupported={:#x}",
                ctl_ent,
                unsupported_entry
            );
            return Err(HypervisorError::VMXUnsupported);
        }
        let unsupported_exit = unsupported_exit_controls(ctl_ext);
        if unsupported_exit != 0 {
            log::error!(
                "Unsupported VM-exit controls are active: ext={:#x} unsupported={:#x}",
                ctl_ext,
                unsupported_exit
            );
            return Err(HypervisorError::VMXUnsupported);
        }

        let (host_leaf7_ebx, host_leaf12_eax) = host_sgx_feature_bits();
        if !sgx_instruction_exiting_ready(host_leaf7_ebx, host_leaf12_eax, ctl_sec) {
            log::error!(
                "SGX is present but cannot be safely hidden because ENCLU does not have a VM-exit control: leaf7_ebx={:#x} leaf12_eax={:#x} sec={:#x}",
                host_leaf7_ebx,
                host_leaf12_eax,
                ctl_sec
            );
            return Err(HypervisorError::VMXUnsupported);
        }
        if !pt_vmx_concealment_ready(host_leaf7_ebx, ctl_sec, ctl_ext, ctl_ent) {
            log::error!(
                "Intel PT is present but VMX concealment controls are incomplete: leaf7_ebx={:#x} sec={:#x} ext={:#x} ent={:#x}",
                host_leaf7_ebx,
                ctl_sec,
                ctl_ext,
                ctl_ent
            );
            return Err(HypervisorError::VMXUnsupported);
        }

        vmwrite_checked(vmcs::control::PINBASED_EXEC_CONTROLS, ctl_pin)?;
        vmwrite_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, ctl_pri)?;
        vmwrite_checked(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, ctl_sec)?;
        vmwrite_checked(vmcs::control::VMENTRY_CONTROLS, ctl_ent)?;
        vmwrite_checked(vmcs::control::VMEXIT_CONTROLS, ctl_ext)?;
        if secondary_control_present(ctl_sec, vmcs::control::SecondaryControls::ENCLS_EXITING) {
            vmwrite_checked(vmcs::control::ENCLS_EXITING_BITMAP_FULL, encls_exiting_bitmap())?;
        }

        {
            use crate::intel::diag;
            use core::sync::atomic::Ordering::Relaxed;
            diag::CTL_PINBASED.store(ctl_pin, Relaxed);
            diag::CTL_PRIMARY.store(ctl_pri, Relaxed);
            diag::CTL_SECONDARY.store(ctl_sec, Relaxed);
            diag::CTL_ENTRY.store(ctl_ent, Relaxed);
            diag::CTL_EXIT.store(ctl_ext, Relaxed);
            log::info!("VMCS CTL pin={:#x} pri={:#x} sec={:#x} ent={:#x} ext={:#x}",
                ctl_pin, ctl_pri, ctl_sec, ctl_ent, ctl_ext);
        }

        unsafe {
            vmwrite_checked(vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64)?;
        };

        const CR4_VMXE: u64 = 1 << 13;
        vmwrite_checked(vmcs::control::CR4_GUEST_HOST_MASK, CR4_VMXE)?;
        vmwrite_checked(vmcs::control::CR4_READ_SHADOW, Cr4::read_raw() & !CR4_VMXE)?;

        vmwrite_checked(vmcs::control::MSR_BITMAPS_ADDR_FULL, PhysicalAddress::pa_from_va(shared_data.msr_bitmap.as_ref() as *const _ as _))?;
        vmwrite_checked(vmcs::control::EXCEPTION_BITMAP, 0u64)?;

        vmwrite_checked(vmcs::control::TSC_OFFSET_FULL, 0u64)?;
        vmwrite_checked(vmcs::control::EPTP_FULL, shared_data.primary_eptp)?;
        vmwrite_checked(vmcs::control::VPID, VPID_TAG)?;

        try_invept_single_context(shared_data.primary_eptp)?;
        try_invvpid_single_context(VPID_TAG)?;

        log::debug!("VMCS Control Fields setup successfully!");

        Ok(())
    }

    /// Retrieves the VMCS revision ID.
    pub fn get_vmcs_revision_id() -> u32 {
        unsafe { (msr::rdmsr(msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}

fn required_primary_controls() -> u64 {
    (vmcs::control::PrimaryControls::SECONDARY_CONTROLS.bits()
        | vmcs::control::PrimaryControls::USE_MSR_BITMAPS.bits()) as u64
}

fn required_secondary_controls() -> u64 {
    (vmcs::control::SecondaryControls::ENABLE_RDTSCP.bits()
        | vmcs::control::SecondaryControls::ENABLE_XSAVES_XRSTORS.bits()
        | vmcs::control::SecondaryControls::ENABLE_INVPCID.bits()
        | vmcs::control::SecondaryControls::ENABLE_VPID.bits()
        | vmcs::control::SecondaryControls::ENABLE_EPT.bits()) as u64
}

const PT_CONCEAL_SECONDARY: u8 = 1;
const PT_CONCEAL_EXIT: u8 = 2;
const PT_CONCEAL_ENTRY: u8 = 4;
const PT_CONCEAL_ALL: u8 = PT_CONCEAL_SECONDARY | PT_CONCEAL_EXIT | PT_CONCEAL_ENTRY;

fn optional_secondary_controls() -> u64 {
    optional_secondary_controls_for_pt_mask(pt_vmx_concealment_mask())
}

fn optional_secondary_controls_for_pt_mask(mask: u8) -> u64 {
    let mut controls = (vmcs::control::SecondaryControls::ENCLS_EXITING.bits()
        | vmcs::control::SecondaryControls::ENCLV_EXITING.bits()) as u64;

    if mask & PT_CONCEAL_SECONDARY != 0 {
        controls |= vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
    }

    controls
}

fn requested_secondary_controls() -> u64 {
    required_secondary_controls() | optional_secondary_controls()
}

fn required_entry_controls() -> u64 {
    vmcs::control::EntryControls::IA32E_MODE_GUEST.bits() as u64
}

fn optional_entry_controls() -> u64 {
    optional_entry_controls_for_pt_mask(pt_vmx_concealment_mask())
}

fn optional_entry_controls_for_pt_mask(mask: u8) -> u64 {
    if mask & PT_CONCEAL_ENTRY != 0 {
        vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits() as u64
    } else {
        0
    }
}

fn requested_entry_controls() -> u64 {
    required_entry_controls() | optional_entry_controls()
}

fn required_exit_controls() -> u64 {
    vmcs::control::ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as u64
}

fn optional_exit_controls() -> u64 {
    optional_exit_controls_for_pt_mask(pt_vmx_concealment_mask())
}

fn optional_exit_controls_for_pt_mask(mask: u8) -> u64 {
    if mask & PT_CONCEAL_EXIT != 0 {
        vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits() as u64
    } else {
        0
    }
}

fn requested_exit_controls() -> u64 {
    required_exit_controls() | optional_exit_controls()
}

fn required_controls_present(required: u64, effective: u64) -> bool {
    effective & required == required
}

fn secondary_control_present(effective: u64, control: vmcs::control::SecondaryControls) -> bool {
    effective & control.bits() as u64 != 0
}

fn pinbased_interrupt_exiting_ready(effective_pinbased: u64) -> bool {
    let unsupported = (vmcs::control::PinbasedControls::EXTERNAL_INTERRUPT_EXITING.bits()
        | vmcs::control::PinbasedControls::VIRTUAL_NMIS.bits()
        | vmcs::control::PinbasedControls::VMX_PREEMPTION_TIMER.bits()
        | vmcs::control::PinbasedControls::POSTED_INTERRUPTS.bits()) as u64;

    effective_pinbased & unsupported == 0
}

fn unsupported_primary_exit_controls(effective_primary: u64) -> u64 {
    let unsupported = (vmcs::control::PrimaryControls::INTERRUPT_WINDOW_EXITING.bits()
        | vmcs::control::PrimaryControls::HLT_EXITING.bits()
        | vmcs::control::PrimaryControls::INVLPG_EXITING.bits()
        | vmcs::control::PrimaryControls::MWAIT_EXITING.bits()
        | vmcs::control::PrimaryControls::RDPMC_EXITING.bits()
        | vmcs::control::PrimaryControls::CR3_LOAD_EXITING.bits()
        | vmcs::control::PrimaryControls::CR3_STORE_EXITING.bits()
        | vmcs::control::PrimaryControls::CR8_LOAD_EXITING.bits()
        | vmcs::control::PrimaryControls::CR8_STORE_EXITING.bits()
        | vmcs::control::PrimaryControls::USE_TPR_SHADOW.bits()
        | vmcs::control::PrimaryControls::NMI_WINDOW_EXITING.bits()
        | vmcs::control::PrimaryControls::MOV_DR_EXITING.bits()
        | vmcs::control::PrimaryControls::UNCOND_IO_EXITING.bits()
        | vmcs::control::PrimaryControls::USE_IO_BITMAPS.bits()
        | vmcs::control::PrimaryControls::MONITOR_TRAP_FLAG.bits()
        | vmcs::control::PrimaryControls::MONITOR_EXITING.bits()
        | vmcs::control::PrimaryControls::PAUSE_EXITING.bits()) as u64;

    effective_primary & unsupported
}

fn unsupported_secondary_controls(effective_secondary: u64) -> u64 {
    let unsupported = (vmcs::control::SecondaryControls::VIRTUALIZE_APIC.bits()
        | vmcs::control::SecondaryControls::DTABLE_EXITING.bits()
        | vmcs::control::SecondaryControls::VIRTUALIZE_X2APIC.bits()
        | vmcs::control::SecondaryControls::UNRESTRICTED_GUEST.bits()
        | vmcs::control::SecondaryControls::VIRTUALIZE_APIC_REGISTER.bits()
        | vmcs::control::SecondaryControls::VIRTUAL_INTERRUPT_DELIVERY.bits()
        | vmcs::control::SecondaryControls::PAUSE_LOOP_EXITING.bits()
        | vmcs::control::SecondaryControls::RDRAND_EXITING.bits()
        | vmcs::control::SecondaryControls::ENABLE_VM_FUNCTIONS.bits()
        | vmcs::control::SecondaryControls::VMCS_SHADOWING.bits()
        | vmcs::control::SecondaryControls::RDSEED_EXITING.bits()
        | vmcs::control::SecondaryControls::ENABLE_PML.bits()
        | vmcs::control::SecondaryControls::EPT_VIOLATION_VE.bits()
        | vmcs::control::SecondaryControls::MODE_BASED_EPT.bits()
        | vmcs::control::SecondaryControls::SUB_PAGE_EPT.bits()
        | vmcs::control::SecondaryControls::INTEL_PT_GUEST_PHYSICAL.bits()
        | vmcs::control::SecondaryControls::USE_TSC_SCALING.bits()
        | vmcs::control::SecondaryControls::ENABLE_USER_WAIT_PAUSE.bits())
        as u64;

    effective_secondary & unsupported
}

fn unsupported_entry_controls(effective_entry: u64) -> u64 {
    let unsupported = (vmcs::control::EntryControls::ENTRY_TO_SMM.bits()
        | vmcs::control::EntryControls::DEACTIVATE_DUAL_MONITOR.bits()
        | vmcs::control::EntryControls::LOAD_IA32_PERF_GLOBAL_CTRL.bits()
        | vmcs::control::EntryControls::LOAD_IA32_PAT.bits()
        | vmcs::control::EntryControls::LOAD_IA32_EFER.bits()
        | vmcs::control::EntryControls::LOAD_IA32_BNDCFGS.bits()
        | vmcs::control::EntryControls::LOAD_IA32_RTIT_CTL.bits()) as u64;

    effective_entry & unsupported
}

fn unsupported_exit_controls(effective_exit: u64) -> u64 {
    let unsupported = (vmcs::control::ExitControls::LOAD_IA32_PERF_GLOBAL_CTRL.bits()
        | vmcs::control::ExitControls::ACK_INTERRUPT_ON_EXIT.bits()
        | vmcs::control::ExitControls::SAVE_IA32_PAT.bits()
        | vmcs::control::ExitControls::LOAD_IA32_PAT.bits()
        | vmcs::control::ExitControls::SAVE_IA32_EFER.bits()
        | vmcs::control::ExitControls::LOAD_IA32_EFER.bits()
        | vmcs::control::ExitControls::SAVE_VMX_PREEMPTION_TIMER.bits()
        | vmcs::control::ExitControls::CLEAR_IA32_BNDCFGS.bits()
        | vmcs::control::ExitControls::CLEAR_IA32_RTIT_CTL.bits()) as u64;

    effective_exit & unsupported
}

const CPUID_7_EBX_SGX: u32 = 1 << 2;
const CPUID_7_EBX_INTEL_PT: u32 = 1 << 25;

fn pt_vmx_concealment_mask() -> u8 {
    pt_vmx_concealment_mask_from_env(
        option_env!("HV_PT_CONCEAL_MASK"),
        option_env!("HV_ENABLE_PT_CONCEAL"),
    )
}

fn pt_vmx_concealment_mask_from_env(mask: Option<&str>, legacy_enable: Option<&str>) -> u8 {
    if legacy_enable == Some("1") {
        return PT_CONCEAL_ALL;
    }

    match mask {
        Some("0") => 0,
        Some("1") => PT_CONCEAL_SECONDARY,
        Some("2") => PT_CONCEAL_EXIT,
        Some("3") => PT_CONCEAL_SECONDARY | PT_CONCEAL_EXIT,
        Some("4") => PT_CONCEAL_ENTRY,
        Some("5") => PT_CONCEAL_SECONDARY | PT_CONCEAL_ENTRY,
        Some("6") => PT_CONCEAL_EXIT | PT_CONCEAL_ENTRY,
        Some("7") => PT_CONCEAL_ALL,
        _ => PT_CONCEAL_ALL,
    }
}

fn host_sgx_feature_bits() -> (u32, u32) {
    let leaf7 = cpuid!(0x7, 0);
    let leaf12_eax = if leaf7.ebx & CPUID_7_EBX_SGX != 0 {
        cpuid!(0x12, 0).eax
    } else {
        0
    };

    (leaf7.ebx, leaf12_eax)
}

fn sgx_instruction_exiting_ready(
    host_leaf7_ebx: u32,
    _host_leaf12_eax: u32,
    _effective_secondary: u64,
) -> bool {
    host_leaf7_ebx & CPUID_7_EBX_SGX == 0
}

fn pt_vmx_concealment_ready(
    host_leaf7_ebx: u32,
    effective_secondary: u64,
    effective_exit: u64,
    effective_entry: u64,
) -> bool {
    pt_vmx_concealment_ready_for_mask(
        pt_vmx_concealment_mask(),
        host_leaf7_ebx,
        effective_secondary,
        effective_exit,
        effective_entry,
    )
}

fn pt_vmx_concealment_ready_for_mask(
    mask: u8,
    host_leaf7_ebx: u32,
    effective_secondary: u64,
    effective_exit: u64,
    effective_entry: u64,
) -> bool {
    if mask != PT_CONCEAL_ALL || host_leaf7_ebx & CPUID_7_EBX_INTEL_PT == 0 {
        return true;
    }

    let secondary_ready = secondary_control_present(
        effective_secondary,
        vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT,
    );
    let exit_ready =
        effective_exit & vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits() as u64 != 0;
    let entry_ready =
        effective_entry & vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits() as u64 != 0;

    secondary_ready && exit_ready && entry_ready
}

fn encls_exiting_bitmap() -> u64 {
    u64::MAX
}

/// Debug implementation to dump the VMCS fields.
impl fmt::Debug for Vmcs {
    /// Formats the VMCS for display.
    ///
    /// # Arguments
    /// * `format` - Formatter instance.
    ///
    /// # Returns
    /// Formatting result.
    #[rustfmt::skip]
    fn fmt(&self, format: &mut fmt::Formatter<'_>) -> fmt::Result {

        format.debug_struct("Vmcs")
            .field("Current VMCS: ", &(self as *const _))
            .field("Revision ID: ", &self.revision_id)

            /* VMCS Guest state fields */
            .field("Guest CR0: ", &vmread(vmcs::guest::CR0))
            .field("Guest CR3: ", &vmread(vmcs::guest::CR3))
            .field("Guest CR4: ", &vmread(vmcs::guest::CR4))
            .field("Guest DR7: ", &vmread(vmcs::guest::DR7))
            .field("Guest RSP: ", &vmread(vmcs::guest::RSP))
            .field("Guest RIP: ", &vmread(vmcs::guest::RIP))
            .field("Guest RFLAGS: ", &vmread(vmcs::guest::RFLAGS))

            .field("Guest CS Selector: ", &vmread(vmcs::guest::CS_SELECTOR))
            .field("Guest SS Selector: ", &vmread(vmcs::guest::SS_SELECTOR))
            .field("Guest DS Selector: ", &vmread(vmcs::guest::DS_SELECTOR))
            .field("Guest ES Selector: ", &vmread(vmcs::guest::ES_SELECTOR))
            .field("Guest FS Selector: ", &vmread(vmcs::guest::FS_SELECTOR))
            .field("Guest GS Selector: ", &vmread(vmcs::guest::GS_SELECTOR))
            .field("Guest LDTR Selector: ", &vmread(vmcs::guest::LDTR_SELECTOR))
            .field("Guest TR Selector: ", &vmread(vmcs::guest::TR_SELECTOR))

            .field("Guest CS Base: ", &vmread(vmcs::guest::CS_BASE))
            .field("Guest SS Base: ", &vmread(vmcs::guest::SS_BASE))
            .field("Guest DS Base: ", &vmread(vmcs::guest::DS_BASE))
            .field("Guest ES Base: ", &vmread(vmcs::guest::ES_BASE))
            .field("Guest FS Base: ", &vmread(vmcs::guest::FS_BASE))
            .field("Guest GS Base: ", &vmread(vmcs::guest::GS_BASE))
            .field("Guest LDTR Base: ", &vmread(vmcs::guest::LDTR_BASE))
            .field("Guest TR Base: ", &vmread(vmcs::guest::TR_BASE))

            .field("Guest CS Limit: ", &vmread(vmcs::guest::CS_LIMIT))
            .field("Guest SS Limit: ", &vmread(vmcs::guest::SS_LIMIT))
            .field("Guest DS Limit: ", &vmread(vmcs::guest::DS_LIMIT))
            .field("Guest ES Limit: ", &vmread(vmcs::guest::ES_LIMIT))
            .field("Guest FS Limit: ", &vmread(vmcs::guest::FS_LIMIT))
            .field("Guest GS Limit: ", &vmread(vmcs::guest::GS_LIMIT))
            .field("Guest LDTR Limit: ", &vmread(vmcs::guest::LDTR_LIMIT))
            .field("Guest TR Limit: ", &vmread(vmcs::guest::TR_LIMIT))

            .field("Guest CS Access Rights: ", &vmread(vmcs::guest::CS_ACCESS_RIGHTS))
            .field("Guest SS Access Rights: ", &vmread(vmcs::guest::SS_ACCESS_RIGHTS))
            .field("Guest DS Access Rights: ", &vmread(vmcs::guest::DS_ACCESS_RIGHTS))
            .field("Guest ES Access Rights: ", &vmread(vmcs::guest::ES_ACCESS_RIGHTS))
            .field("Guest FS Access Rights: ", &vmread(vmcs::guest::FS_ACCESS_RIGHTS))
            .field("Guest GS Access Rights: ", &vmread(vmcs::guest::GS_ACCESS_RIGHTS))
            .field("Guest LDTR Access Rights: ", &vmread(vmcs::guest::LDTR_ACCESS_RIGHTS))
            .field("Guest TR Access Rights: ", &vmread(vmcs::guest::TR_ACCESS_RIGHTS))

            .field("Guest GDTR Base: ", &vmread(vmcs::guest::GDTR_BASE))
            .field("Guest IDTR Base: ", &vmread(vmcs::guest::IDTR_BASE))
            .field("Guest GDTR Limit: ", &vmread(vmcs::guest::GDTR_LIMIT))
            .field("Guest IDTR Limit: ", &vmread(vmcs::guest::IDTR_LIMIT))

            .field("Guest IA32_DEBUGCTL_FULL: ", &vmread(vmcs::guest::IA32_DEBUGCTL_FULL))
            .field("Guest IA32_SYSENTER_CS: ", &vmread(vmcs::guest::IA32_SYSENTER_CS))
            .field("Guest IA32_SYSENTER_ESP: ", &vmread(vmcs::guest::IA32_SYSENTER_ESP))
            .field("Guest IA32_SYSENTER_EIP: ", &vmread(vmcs::guest::IA32_SYSENTER_EIP))
            .field("Guest VMCS Link Pointer: ", &vmread(vmcs::guest::LINK_PTR_FULL))

            /* VMCS Host state fields */
            .field("Host CR0: ", &vmread(vmcs::host::CR0))
            .field("Host CR3: ", &vmread(vmcs::host::CR3))
            .field("Host CR4: ", &vmread(vmcs::host::CR4))
            .field("Host RSP: ", &vmread(vmcs::host::RSP))
            .field("Host RIP: ", &vmread(vmcs::host::RIP))
            .field("Host CS Selector: ", &vmread(vmcs::host::CS_SELECTOR))
            .field("Host SS Selector: ", &vmread(vmcs::host::SS_SELECTOR))
            .field("Host DS Selector: ", &vmread(vmcs::host::DS_SELECTOR))
            .field("Host ES Selector: ", &vmread(vmcs::host::ES_SELECTOR))
            .field("Host FS Selector: ", &vmread(vmcs::host::FS_SELECTOR))
            .field("Host GS Selector: ", &vmread(vmcs::host::GS_SELECTOR))
            .field("Host TR Selector: ", &vmread(vmcs::host::TR_SELECTOR))
            .field("Host FS Base: ", &vmread(vmcs::host::FS_BASE))
            .field("Host GS Base: ", &vmread(vmcs::host::GS_BASE))
            .field("Host TR Base: ", &vmread(vmcs::host::TR_BASE))
            .field("Host GDTR Base: ", &vmread(vmcs::host::GDTR_BASE))
            .field("Host IDTR Base: ", &vmread(vmcs::host::IDTR_BASE))
            .field("Host IA32_SYSENTER_CS: ", &vmread(vmcs::host::IA32_SYSENTER_CS))
            .field("Host IA32_SYSENTER_ESP: ", &vmread(vmcs::host::IA32_SYSENTER_ESP))
            .field("Host IA32_SYSENTER_EIP: ", &vmread(vmcs::host::IA32_SYSENTER_EIP))

            /* VMCS Control fields */
            .field("Primary Proc Based Execution Controls: ", &vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS))
            .field("Secondary Proc Based Execution Controls: ", &vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS))
            .field("VM Entry Controls: ", &vmread(vmcs::control::VMENTRY_CONTROLS))
            .field("VM Exit Controls: ", &vmread(vmcs::control::VMEXIT_CONTROLS))
            .field("Pin Based Execution Controls: ", &vmread(vmcs::control::PINBASED_EXEC_CONTROLS))
            .field("CR0 Read Shadow: ", &vmread(vmcs::control::CR0_READ_SHADOW))
            .field("CR4 Read Shadow: ", &vmread(vmcs::control::CR4_READ_SHADOW))
            .field("MSR Bitmaps Address: ", &vmread(vmcs::control::MSR_BITMAPS_ADDR_FULL))
            .field("EPT Pointer: ", &vmread(vmcs::control::EPTP_FULL))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_controls_must_all_be_present() {
        assert!(required_controls_present(0b1010, 0b1110));
        assert!(!required_controls_present(0b1010, 0b0010));
    }

    #[test]
    fn primary_controls_do_not_request_dynamic_tsc_offsetting_by_default() {
        let required = required_primary_controls();
        let tsc_offsetting = vmcs::control::PrimaryControls::USE_TSC_OFFSETTING.bits() as u64;

        assert_eq!(required & tsc_offsetting, 0);
    }

    #[test]
    fn pt_vmx_concealment_can_be_disabled_by_env() {
        let secondary_pt = vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
        let entry_pt = vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
        let exit_pt = vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits() as u64;

        assert_eq!(pt_vmx_concealment_mask_from_env(Some("0"), None), 0);
        assert_eq!(optional_secondary_controls_for_pt_mask(0) & secondary_pt, 0);
        assert_eq!(optional_entry_controls_for_pt_mask(0) & entry_pt, 0);
        assert_eq!(optional_exit_controls_for_pt_mask(0) & exit_pt, 0);
    }

    #[test]
    fn requested_controls_enable_pt_vmx_concealment_by_default() {
        let secondary_pt = vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
        let entry_pt = vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
        let exit_pt = vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits() as u64;

        assert_eq!(pt_vmx_concealment_mask_from_env(None, None), PT_CONCEAL_ALL);
        assert_eq!(requested_secondary_controls() & secondary_pt, secondary_pt);
        assert_eq!(requested_entry_controls() & entry_pt, entry_pt);
        assert_eq!(requested_exit_controls() & exit_pt, exit_pt);
    }

    #[test]
    fn intel_pt_hosts_do_not_require_vmx_concealment_when_not_requested() {
        let intel_pt = 1 << 25;

        assert!(pt_vmx_concealment_ready_for_mask(0, 0, 0, 0, 0));
        assert!(pt_vmx_concealment_ready_for_mask(0, intel_pt, 0, 0, 0));
    }

    #[test]
    fn pt_vmx_concealment_mask_can_select_individual_controls() {
        let secondary_pt = vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
        let entry_pt = vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
        let exit_pt = vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits() as u64;

        assert_eq!(pt_vmx_concealment_mask_from_env(None, None), PT_CONCEAL_ALL);
        assert_eq!(pt_vmx_concealment_mask_from_env(Some("0"), None), 0);
        assert_eq!(pt_vmx_concealment_mask_from_env(Some("1"), None), 1);
        assert_eq!(pt_vmx_concealment_mask_from_env(Some("2"), None), 2);
        assert_eq!(pt_vmx_concealment_mask_from_env(Some("4"), None), 4);
        assert_eq!(pt_vmx_concealment_mask_from_env(Some("7"), None), 7);
        assert_eq!(pt_vmx_concealment_mask_from_env(None, Some("1")), 7);

        assert_eq!(
            optional_secondary_controls_for_pt_mask(1) & secondary_pt,
            secondary_pt
        );
        assert_eq!(optional_entry_controls_for_pt_mask(1) & entry_pt, 0);
        assert_eq!(optional_exit_controls_for_pt_mask(1) & exit_pt, 0);

        assert_eq!(optional_secondary_controls_for_pt_mask(2) & secondary_pt, 0);
        assert_eq!(optional_entry_controls_for_pt_mask(2) & entry_pt, 0);
        assert_eq!(optional_exit_controls_for_pt_mask(2) & exit_pt, exit_pt);

        assert_eq!(optional_secondary_controls_for_pt_mask(4) & secondary_pt, 0);
        assert_eq!(optional_entry_controls_for_pt_mask(4) & entry_pt, entry_pt);
        assert_eq!(optional_exit_controls_for_pt_mask(4) & exit_pt, 0);
    }

    #[test]
    fn pt_vmx_concealment_readiness_requires_complete_controls_only_for_full_mask() {
        let intel_pt = 1 << 25;
        let secondary_pt = vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
        let entry_pt = vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits() as u64;
        let exit_pt = vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits() as u64;

        assert!(pt_vmx_concealment_ready_for_mask(
            1,
            intel_pt,
            secondary_pt,
            0,
            0
        ));
        assert!(!pt_vmx_concealment_ready_for_mask(
            7,
            intel_pt,
            secondary_pt,
            0,
            entry_pt
        ));
        assert!(pt_vmx_concealment_ready_for_mask(
            7,
            intel_pt,
            secondary_pt,
            exit_pt,
            entry_pt
        ));
    }

    #[test]
    fn external_interrupt_exiting_is_rejected_without_irq_delivery_support() {
        let ext_int = vmcs::control::PinbasedControls::EXTERNAL_INTERRUPT_EXITING.bits() as u64;
        let virtual_nmis = vmcs::control::PinbasedControls::VIRTUAL_NMIS.bits() as u64;
        let preemption_timer = vmcs::control::PinbasedControls::VMX_PREEMPTION_TIMER.bits() as u64;
        let posted_interrupts = vmcs::control::PinbasedControls::POSTED_INTERRUPTS.bits() as u64;

        assert!(pinbased_interrupt_exiting_ready(0));
        assert!(!pinbased_interrupt_exiting_ready(ext_int));
        assert!(!pinbased_interrupt_exiting_ready(virtual_nmis));
        assert!(!pinbased_interrupt_exiting_ready(preemption_timer));
        assert!(!pinbased_interrupt_exiting_ready(posted_interrupts));
    }

    #[test]
    fn unsupported_forced_primary_exit_controls_are_rejected() {
        let baseline = required_primary_controls();
        let hlt = vmcs::control::PrimaryControls::HLT_EXITING.bits() as u64;
        let rdpmc = vmcs::control::PrimaryControls::RDPMC_EXITING.bits() as u64;
        let io = vmcs::control::PrimaryControls::UNCOND_IO_EXITING.bits() as u64;

        assert_eq!(unsupported_primary_exit_controls(baseline), 0);
        assert_ne!(unsupported_primary_exit_controls(baseline | hlt), 0);
        assert_ne!(unsupported_primary_exit_controls(baseline | rdpmc), 0);
        assert_ne!(unsupported_primary_exit_controls(baseline | io), 0);
    }

    #[test]
    fn unsupported_forced_secondary_controls_are_rejected() {
        let baseline = requested_secondary_controls();
        let vmfunc = vmcs::control::SecondaryControls::ENABLE_VM_FUNCTIONS.bits() as u64;
        let pml = vmcs::control::SecondaryControls::ENABLE_PML.bits() as u64;
        let tsc_scaling = vmcs::control::SecondaryControls::USE_TSC_SCALING.bits() as u64;
        let user_wait = vmcs::control::SecondaryControls::ENABLE_USER_WAIT_PAUSE.bits() as u64;

        assert_eq!(unsupported_secondary_controls(baseline), 0);
        assert_ne!(unsupported_secondary_controls(baseline | vmfunc), 0);
        assert_ne!(unsupported_secondary_controls(baseline | pml), 0);
        assert_ne!(unsupported_secondary_controls(baseline | tsc_scaling), 0);
        assert_ne!(unsupported_secondary_controls(baseline | user_wait), 0);
    }

    #[test]
    fn unsupported_forced_entry_and_exit_controls_are_rejected() {
        let entry = requested_entry_controls();
        let exit = requested_exit_controls();
        let entry_efer = vmcs::control::EntryControls::LOAD_IA32_EFER.bits() as u64;
        let exit_efer = vmcs::control::ExitControls::LOAD_IA32_EFER.bits() as u64;
        let exit_ack = vmcs::control::ExitControls::ACK_INTERRUPT_ON_EXIT.bits() as u64;

        assert_eq!(unsupported_entry_controls(entry), 0);
        assert_eq!(unsupported_exit_controls(exit), 0);
        assert_ne!(unsupported_entry_controls(entry | entry_efer), 0);
        assert_ne!(unsupported_exit_controls(exit | exit_efer), 0);
        assert_ne!(unsupported_exit_controls(exit | exit_ack), 0);
    }

    #[test]
    fn requested_secondary_controls_enable_sgx_instruction_exiting_when_supported() {
        let encls = vmcs::control::SecondaryControls::ENCLS_EXITING.bits() as u64;
        let enclv = vmcs::control::SecondaryControls::ENCLV_EXITING.bits() as u64;

        assert_eq!(requested_secondary_controls() & encls, encls);
        assert_eq!(requested_secondary_controls() & enclv, enclv);
    }

    #[test]
    fn sgx_hosts_are_rejected_because_enclu_cannot_be_exited() {
        let sgx_leaf7_ebx = 1 << 2;
        let sgx_leaf12_enclv = 1 << 5;
        let encls = vmcs::control::SecondaryControls::ENCLS_EXITING.bits() as u64;
        let enclv = vmcs::control::SecondaryControls::ENCLV_EXITING.bits() as u64;

        assert!(sgx_instruction_exiting_ready(0, 0, 0));
        assert!(!sgx_instruction_exiting_ready(sgx_leaf7_ebx, 0, 0));
        assert!(!sgx_instruction_exiting_ready(sgx_leaf7_ebx, 0, encls));
        assert!(!sgx_instruction_exiting_ready(
            sgx_leaf7_ebx,
            sgx_leaf12_enclv,
            encls
        ));
        assert!(!sgx_instruction_exiting_ready(
            sgx_leaf7_ebx,
            sgx_leaf12_enclv,
            encls | enclv
        ));
    }

    #[test]
    fn guest_state_setup_surfaces_vmwrite_failures() {
        let _setup: fn(
            &CONTEXT,
            &Box<DescriptorTables, KernelAlloc>,
            &mut GuestRegisters,
        ) -> Result<(), HypervisorError> = Vmcs::setup_guest_registers_state;
    }
}
