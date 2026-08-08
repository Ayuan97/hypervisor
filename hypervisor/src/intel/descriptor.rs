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

// GDTR/IDTR limits are 16-bit byte counts. Reserve the architectural maximum
// before SMP launch so copying either table can never grow a Vec while another
// processor is already in VMX non-root mode.
const MAX_DESCRIPTOR_TABLE_U64S: usize = (u16::MAX as usize + 1) / core::mem::size_of::<u64>();

const fn descriptor_table_u64s(limit: u16) -> usize {
    (limit as usize + 1) / core::mem::size_of::<u64>()
}

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

    /// Creates host-table storage whose backing allocations cannot grow when
    /// the currently loaded GDT and IDT are copied on the target processor.
    pub fn new_preallocated_for_host() -> Result<Self, HypervisorError> {
        let mut tables = Self::new();
        tables
            .global_descriptor_table
            .try_reserve_exact(MAX_DESCRIPTOR_TABLE_U64S)
            .map_err(|_| HypervisorError::OutOfMemory)?;
        tables
            .interrupt_descriptor_table
            .try_reserve_exact(MAX_DESCRIPTOR_TABLE_U64S)
            .map_err(|_| HypervisorError::OutOfMemory)?;
        Ok(tables)
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

        descriptor_tables.copy_current_gdt()?;
        descriptor_tables.copy_current_idt()?;

        super::host_idt::patch_host_idt(&mut descriptor_tables.interrupt_descriptor_table);
        super::host_idt::record_host_idt_descriptor(
            &descriptor_tables.interrupt_descriptor_table,
            descriptor_tables.idtr.base as u64,
            descriptor_tables.idtr.limit as u64,
        );

        log::trace!("Initialized descriptor tables for host");
        Ok(())
    }

    /// Copies the current GDT.
    fn copy_current_gdt(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Copying current GDT");

        // Get the current GDTR
        let current_gdtr = sgdt();

        // Create a slice from the current GDT entries.
        let current_gdt = Self::from_pointer(&current_gdtr);

        Self::replace_preallocated_table(&mut self.global_descriptor_table, current_gdt)?;

        // Create a new GDTR from the new GDT.
        let new_gdtr =
            DescriptorTablePointer::new_from_slice(self.global_descriptor_table.as_slice());

        self.gdtr = new_gdtr;
        log::trace!("Copied current GDT");
        Ok(())
    }

    /// Copies the current IDT.
    fn copy_current_idt(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Copying current IDT");

        // Get the current IDTR
        let current_idtr = sidt();

        // Create a slice from the current IDT entries.
        let current_idt = Self::from_pointer(&current_idtr);

        Self::replace_preallocated_table(&mut self.interrupt_descriptor_table, current_idt)?;

        // Create a new IDTR from the new IDT.
        let new_idtr =
            DescriptorTablePointer::new_from_slice(self.interrupt_descriptor_table.as_slice());

        self.idtr = new_idtr; // Use the same IDTR as it points to the correct base and limit
        log::trace!("Copied current IDT");
        Ok(())
    }

    fn replace_preallocated_table(
        destination: &mut Vec<u64>,
        source: &[u64],
    ) -> Result<(), HypervisorError> {
        if source.len() > destination.capacity() {
            return Err(HypervisorError::OutOfMemory);
        }
        destination.clear();
        destination.extend_from_slice(source);
        Ok(())
    }

    /// Gets the table as a slice from the pointer.
    pub fn from_pointer(pointer: &DescriptorTablePointer<u64>) -> &[u64] {
        unsafe {
            core::slice::from_raw_parts(
                pointer.base.cast::<u64>(),
                descriptor_table_u64s(pointer.limit),
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

    #[test]
    fn preallocated_copy_reuses_existing_vector_storage() {
        let mut destination = Vec::with_capacity(4);
        let original = destination.as_ptr();

        DescriptorTables::replace_preallocated_table(&mut destination, &[1, 2, 3, 4])
            .unwrap();

        assert_eq!(destination, [1, 2, 3, 4]);
        assert_eq!(destination.as_ptr(), original);
        assert!(DescriptorTables::replace_preallocated_table(
            &mut destination,
            &[1, 2, 3, 4, 5]
        )
        .is_err());
    }

    #[test]
    fn host_preallocation_covers_the_architectural_limit() {
        let tables = DescriptorTables::new_preallocated_for_host().unwrap();

        assert!(tables.global_descriptor_table.capacity() >= MAX_DESCRIPTOR_TABLE_U64S);
        assert!(tables.interrupt_descriptor_table.capacity() >= MAX_DESCRIPTOR_TABLE_U64S);
    }

    #[test]
    fn maximum_descriptor_limit_does_not_wrap() {
        assert_eq!(descriptor_table_u64s(u16::MAX), MAX_DESCRIPTOR_TABLE_U64S);
    }
}
