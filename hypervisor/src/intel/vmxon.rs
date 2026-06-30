//! A module responsible for managing the VMXON region and enabling VMX operations.
//!
//! This module provides functionality to set up the VMXON region in memory and
//! enable VMX operations. It also offers utility functions for adjusting control
//! registers to facilitate VMX operations.

use x86_64::registers::control::Cr4;
use {
    crate::{
        error::HypervisorError,
        intel::{support::vmxon, vmcs::Vmcs},
        utils::{addresses::PhysicalAddress, alloc::PhysicalAllocator},
    },
    alloc::boxed::Box,
    bitfield::BitMut,
    x86::current::paging::BASE_PAGE_SIZE,
};

const CR4_VMX_ENABLE_BIT: u64 = 1 << 13;
const VMX_LOCK_BIT: u64 = 1 << 0;
const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

/// A representation of the VMXON region in memory.
///
/// The VMXON region is essential for enabling VMX operations on the CPU.
/// This structure offers methods for setting up the VMXON region, enabling VMX operations,
/// and performing related tasks.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.11.5 VMXON Region
#[repr(C, align(4096))]
pub struct Vmxon {
    pub revision_id: u32,
    pub data: [u8; BASE_PAGE_SIZE - 4],
}

#[derive(Debug, Copy, Clone)]
pub struct ControlRegisterSnapshot {
    cr0: usize,
    cr4: u64,
}

impl ControlRegisterSnapshot {
    pub fn capture() -> Self {
        Self {
            cr0: unsafe { x86::controlregs::cr0().bits() },
            cr4: Cr4::read_raw(),
        }
    }

    pub fn restore(self) {
        unsafe {
            Cr4::write_raw(self.cr4);
            x86::controlregs::cr0_write(x86::controlregs::Cr0::from_bits_truncate(self.cr0));
        }
    }
}

impl Vmxon {
    /// Sets up the VMXON region and enables VMX operations.
    ///
    /// # Arguments
    /// * `vmxon_region` - A mutable reference to the VMXON region in memory.
    ///
    /// # Returns
    /// A result indicating success or an error.
    pub fn setup(vmxon_region: &mut Box<Vmxon, PhysicalAllocator>) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMXON region");
        let control_registers = ControlRegisterSnapshot::capture();

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        log::trace!("Enabling Virtual Machine Extensions (VMX)");
        if let Err(error) = Self::enable_vmx_operation() {
            control_registers.restore();
            return Err(error);
        }

        let vmxon_region_physical_address =
            PhysicalAddress::pa_from_va(vmxon_region.as_ref() as *const _ as _);

        if vmxon_region_physical_address == 0 {
            control_registers.restore();
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::trace!("VMXON Region Virtual Address: {:p}", vmxon_region);
        log::trace!(
            "VMXON Region Physical Addresss: 0x{:x}",
            vmxon_region_physical_address
        );

        vmxon_region.revision_id = Vmcs::get_vmcs_revision_id();
        vmxon_region.as_mut().revision_id.set_bit(31, false);

        // Enable VMX operation.
        if let Err(error) = vmxon(vmxon_region_physical_address) {
            control_registers.restore();
            return Err(error);
        }

        log::debug!("VMXON setup successfully!");

        Ok(())
    }

    /// Enables VMX operation by setting appropriate bits and executing the VMXON instruction.
    fn enable_vmx_operation() -> Result<(), HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        log::trace!("Setting Lock Bit set via IA32_FEATURE_CONTROL");
        Self::set_lock_bit()?;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.8 RESTRICTIONS ON VMX OPERATION */
        log::trace!("Adjusting Control Registers");
        Self::adjust_control_registers();

        let cr4 = cr4_with_vmxe(Cr4::read_raw());
        unsafe { Cr4::write_raw(cr4) };

        Ok(())
    }

    /// Sets the lock bit in IA32_FEATURE_CONTROL if necessary.
    fn set_lock_bit() -> Result<(), HypervisorError> {
        let ia32_feature_control = unsafe { x86::msr::rdmsr(x86::msr::IA32_FEATURE_CONTROL) };

        if let Some(updated_feature_control) =
            feature_control_update_for_vmxon(ia32_feature_control)?
        {
            unsafe { x86::msr::wrmsr(x86::msr::IA32_FEATURE_CONTROL, updated_feature_control) };
        }

        Ok(())
    }

    /// Adjusts control registers by setting mandatory bits.
    fn adjust_control_registers() {
        Self::set_cr0_bits();
        Self::set_cr4_bits();
    }

    /// Modifies CR0 to set and clear mandatory bits.
    fn set_cr0_bits() {
        let ia32_vmx_cr0_fixed0 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR0_FIXED1) };

        let cr0 = cr0_with_vmx_fixed_bits(
            unsafe { x86::controlregs::cr0().bits() } as u64,
            ia32_vmx_cr0_fixed0,
            ia32_vmx_cr0_fixed1,
        );

        unsafe {
            x86::controlregs::cr0_write(x86::controlregs::Cr0::from_bits_truncate(cr0 as usize))
        };
    }

    /// Modifies CR4 to set and clear mandatory bits.
    fn set_cr4_bits() {
        let ia32_vmx_cr4_fixed0 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR4_FIXED1) };

        let cr4 =
            cr4_with_vmx_fixed_bits(Cr4::read_raw(), ia32_vmx_cr4_fixed0, ia32_vmx_cr4_fixed1);

        unsafe { Cr4::write_raw(cr4) };
    }
}

fn feature_control_update_for_vmxon(
    ia32_feature_control: u64,
) -> Result<Option<u64>, HypervisorError> {
    if ia32_feature_control & VMX_LOCK_BIT == 0 {
        return Ok(Some(
            ia32_feature_control | VMX_LOCK_BIT | VMXON_OUTSIDE_SMX,
        ));
    }

    if ia32_feature_control & VMXON_OUTSIDE_SMX == 0 {
        return Err(HypervisorError::VMXBIOSLock);
    }

    Ok(None)
}

fn cr4_with_vmxe(cr4: u64) -> u64 {
    cr4 | CR4_VMX_ENABLE_BIT
}

fn cr0_with_vmx_fixed_bits(current: u64, fixed0: u64, fixed1: u64) -> u64 {
    (current | fixed0) & fixed1
}

fn cr4_with_vmx_fixed_bits(current: u64, fixed0: u64, fixed1: u64) -> u64 {
    (current | fixed0) & fixed1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_feature_control_without_vmxon_outside_smx_is_rejected() {
        let locked_without_outside_smx = 1u64 << 0;

        assert!(matches!(
            feature_control_update_for_vmxon(locked_without_outside_smx),
            Err(HypervisorError::VMXBIOSLock)
        ));
    }

    #[test]
    fn unlocked_feature_control_is_locked_with_vmxon_outside_smx_enabled() {
        let original = 0x20u64;

        assert_eq!(
            feature_control_update_for_vmxon(original).unwrap(),
            Some(original | (1u64 << 0) | (1u64 << 2))
        );
    }

    #[test]
    fn locked_feature_control_with_vmxon_outside_smx_needs_no_write() {
        let locked_with_outside_smx = (1u64 << 0) | (1u64 << 2);

        assert_eq!(
            feature_control_update_for_vmxon(locked_with_outside_smx).unwrap(),
            None
        );
    }

    #[test]
    fn cr4_vmxe_update_sets_bit_without_clearing_existing_bits() {
        assert_eq!(cr4_with_vmxe(0x100), 0x100 | (1u64 << 13));
    }

    #[test]
    fn cr0_fixed_bits_are_set_and_disallowed_bits_are_cleared() {
        let current = 0b1000u64;
        let fixed0 = 0b0011u64;
        let fixed1 = 0b0111u64;

        assert_eq!(cr0_with_vmx_fixed_bits(current, fixed0, fixed1), 0b0011);
    }

    #[test]
    fn cr4_fixed_bits_are_set_and_disallowed_bits_are_cleared() {
        let current = 0b1000u64;
        let fixed0 = 0b0010u64;
        let fixed1 = 0b0111u64;

        assert_eq!(cr4_with_vmx_fixed_bits(current, fixed0, fixed1), 0b0010);
    }
}
