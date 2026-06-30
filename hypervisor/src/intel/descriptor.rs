//! This module defines and manages the descriptor tables (GDT and IDT) for both the host and guest.
//! It provides utilities to capture, initialize, and manage these tables.

use {
    crate::{
        error::HypervisorError,
        utils::alloc::KernelAlloc,
        utils::instructions::{sgdt, sidt},
    },
    alloc::{boxed::Box, vec::Vec},
    x86::dtables::DescriptorTablePointer,
};

/// Represents the descriptor tables (GDT and IDT) for the host.
/// Contains the GDT and IDT along with their respective register pointers.
#[repr(C, align(4096))]
pub struct DescriptorTables {
    /// Global Descriptor Table (GDT) for the host.
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.5.1 Segment Descriptor Tables
    pub global_descriptor_table: Vec<u64>,

    /// GDTR holds the address and size of the GDT.
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 2.4.1 Global Descriptor Table Register (GDTR)
    pub gdtr: DescriptorTablePointer<u64>,

    /// Interrupt Descriptor Table (IDT) for the host.
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 6.10 INTERRUPT DESCRIPTOR TABLE (IDT)
    pub interrupt_descriptor_table: Vec<u64>,

    /// IDTR holds the address and size of the IDT.
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 2.4.3 IDTR Interrupt Descriptor Table Register
    pub idtr: DescriptorTablePointer<u64>,
}

impl DescriptorTables {
    /// Creates descriptor table storage with valid empty vectors and empty GDTR/IDTR pointers.
    pub fn new() -> Self {
        Self {
            global_descriptor_table: Vec::new(),
            gdtr: DescriptorTablePointer::default(),
            interrupt_descriptor_table: Vec::new(),
            idtr: DescriptorTablePointer::default(),
        }
    }

    /// Captures the currently loaded GDT and IDT for the guest.
    pub fn initialize_for_guest(
        descriptor_tables: &mut Box<DescriptorTables, KernelAlloc>,
    ) -> Result<(), HypervisorError> {
        log::trace!("Capturing current Global Descriptor Table (GDT) and Interrupt Descriptor Table (IDT) for guest");

        // Capture the current GDT and IDT.
        descriptor_tables.gdtr = sgdt();
        descriptor_tables.idtr = sidt();

        // Note: We don't need to create new tables for the guest;
        // we just capture the current ones.

        log::trace!("Captured GDT and IDT for guest successfully!");

        Ok(())
    }

    /// Initializes and returns the descriptor tables (GDT and IDT) for the host.
    pub fn initialize_for_host(
        descriptor_tables: &mut Box<DescriptorTables, KernelAlloc>,
    ) -> Result<(), HypervisorError> {
        log::trace!("Initializing descriptor tables for host");

        descriptor_tables.copy_current_gdt();
        descriptor_tables.copy_current_idt();

        super::host_idt::patch_host_idt(&mut descriptor_tables.interrupt_descriptor_table);

        log::trace!("Initialized descriptor tables for host");
        Ok(())
    }

    /// Copies the current GDT.
    fn copy_current_gdt(&mut self) {
        log::trace!("Copying current GDT");

        // Get the current GDTR
        let current_gdtr = sgdt();

        // Create a slice from the current GDT entries.
        let current_gdt = Self::from_pointer(&current_gdtr);

        // Create a new GDT from the slice.
        let new_gdt = current_gdt.to_vec();

        // Create a new GDTR from the new GDT.
        let new_gdtr = DescriptorTablePointer::new_from_slice(new_gdt.as_slice());

        // Store the new GDT in the DescriptorTables structure
        self.global_descriptor_table = new_gdt;
        self.gdtr = new_gdtr;
        log::trace!("Copied current GDT");
    }

    /// Copies the current IDT.
    fn copy_current_idt(&mut self) {
        log::trace!("Copying current IDT");

        // Get the current IDTR
        let current_idtr = sidt();

        // Create a slice from the current IDT entries.
        let current_idt = Self::from_pointer(&current_idtr);

        // Create a new IDT from the slice.
        let new_idt = current_idt.to_vec();

        // Create a new IDTR from the new IDT.
        let new_idtr = DescriptorTablePointer::new_from_slice(new_idt.as_slice());

        // Store the new IDT in the DescriptorTables structure
        self.interrupt_descriptor_table = new_idt;
        self.idtr = new_idtr; // Use the same IDTR as it points to the correct base and limit
        log::trace!("Copied current IDT");
    }

    /// Gets the table as a slice from the pointer.
    pub fn from_pointer(pointer: &DescriptorTablePointer<u64>) -> &[u64] {
        unsafe {
            core::slice::from_raw_parts(
                pointer.base.cast::<u64>(),
                (pointer.limit + 1) as usize / core::mem::size_of::<u64>(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_initializes_valid_empty_vectors() {
        let tables = DescriptorTables::new();

        assert!(tables.global_descriptor_table.is_empty());
        assert!(tables.interrupt_descriptor_table.is_empty());

        let gdtr_base = tables.gdtr.base;
        let gdtr_limit = tables.gdtr.limit;
        let idtr_base = tables.idtr.base;
        let idtr_limit = tables.idtr.limit;

        assert!(gdtr_base.is_null());
        assert_eq!(gdtr_limit, 0);
        assert!(idtr_base.is_null());
        assert_eq!(idtr_limit, 0);
    }
}
