//! A module for handling Memory Type Range Registers (MTRRs) in x86 systems.
//! It provides functionality to build a map of MTRRs and their corresponding memory ranges
//! and types, following the specifications of the Intel® 64 and IA-32 Architectures Software Developer's Manual: 12.11 MEMORY TYPE RANGE REGISTERS (MTRRS)
//!
//! Credits to Neri https://github.com/neri/maystorm/blob/develop/system/src/arch/x64/cpu.rs

use {
    crate::utils::{addresses::PhysicalAddress, instructions::rdmsr},
    alloc::vec::Vec,
    x86::msr::{IA32_MTRRCAP, IA32_MTRR_DEF_TYPE, IA32_MTRR_PHYSBASE0, IA32_MTRR_PHYSMASK0},
};

/// Represents the different types of memory as defined by MTRRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// Memory type: Uncacheable (UC)
    Uncacheable = 0,
    /// Memory type: Write-combining (WC)
    WriteCombining = 1,
    /// Memory type: Write-through (WT)
    WriteThrough = 4,
    /// Memory type: Write-protected (WP)
    WriteProtected = 5,
    /// Memory type: Write-back (WB)
    WriteBack = 6,
}

/// Represents a Mttr range descriptor.
pub struct Mtrr {
    descriptors: Vec<MtrrRangeDescriptor>,
    default_type: MemoryType,
}

impl Mtrr {
    /// Builds a map of the MTRR memory ranges currently in use.
    ///
    /// # Returns
    /// A vector of `MtrrRangeDescriptor` representing each enabled memory range.
    pub fn new() -> Self {
        let default_type = Self::from_raw(rdmsr(IA32_MTRR_DEF_TYPE) as u8);
        log::trace!("MTRR default type: {:?}", default_type);

        let mut descriptors = Vec::new();

        for index in Self::indexes() {
            let item = Self::get(index);

            if item.is_enabled && item.mem_type != default_type {
                let end_address = Self::calculate_end_address(item.base.pa(), item.mask);

                let descriptor = MtrrRangeDescriptor {
                    base_address: item.base.pa(),
                    end_address,
                    memory_type: item.mem_type,
                };

                descriptors.push(descriptor);
                log::trace!(
                    "MTRR Range: Base=0x{:x} End=0x{:x} Type={:?}",
                    descriptor.base_address,
                    descriptor.end_address,
                    descriptor.memory_type
                );
            }
        }

        log::trace!("Total MTRR Ranges Committed: {}", descriptors.len());
        Self {
            descriptors,
            default_type,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(default_type: MemoryType, descriptors: &[MtrrRangeDescriptor]) -> Self {
        Self {
            descriptors: descriptors.to_vec(),
            default_type,
        }
    }

    /// Finds the memory type for a given physical address range based on the MTRR map.
    ///
    /// This method examines the MTRR map to find the appropriate memory type for the
    /// specified physical address range. It respects the precedence of different memory
    /// types, with Uncacheable (UC) having the highest precedence.
    /// If no matching range is found, it defaults to WriteBack.
    ///
    /// # Arguments
    /// * `mtrr_map` - The MTRR map to search within.
    /// * `range` - The physical address range for which to find the memory type.
    ///
    /// # Returns
    /// The memory type for the given address range, or a default of WriteBack if no matching range is found.
    pub fn find(&self, range: core::ops::Range<u64>) -> Option<MemoryType> {
        let mut memory_type: Option<MemoryType> = None;
        let range_last = range.end.saturating_sub(1);

        for descriptor in self.descriptors.iter() {
            if range.start <= descriptor.end_address && range_last >= descriptor.base_address {
                match descriptor.memory_type {
                    MemoryType::Uncacheable => return Some(MemoryType::Uncacheable),
                    MemoryType::WriteCombining => memory_type = Some(MemoryType::WriteCombining),
                    MemoryType::WriteThrough => memory_type = Some(MemoryType::WriteThrough),
                    MemoryType::WriteProtected => memory_type = Some(MemoryType::WriteProtected),
                    MemoryType::WriteBack => memory_type = Some(MemoryType::WriteBack),
                }
            }
        }

        memory_type.or(Some(self.default_type))
    }

    /// Calculates the end address of an MTRR memory range.
    ///
    /// # Arguments
    /// * `base` - The base address of the memory range.
    /// * `mask` - The mask defining the size of the range.
    ///
    /// # Returns
    /// The end address of the memory range.
    fn calculate_end_address(base: u64, mask: u64) -> u64 {
        let first_set_bit = Self::bit_scan_forward(mask);
        let size = 1 << first_set_bit;
        base + size - 1
    }

    /// Performs a Bit Scan Forward (BSF) operation to find the index of the first set bit.
    ///
    /// # Arguments
    /// * `value` - The value to scan.
    ///
    /// # Returns
    /// The index of the first set bit.
    fn bit_scan_forward(value: u64) -> u64 {
        let result: u64;
        unsafe { core::arch::asm!("bsf {}, {}", out(reg) result, in(reg) value) };
        result
    }

    /// Retrieves the count of variable range MTRRs.
    ///
    /// Reads the IA32_MTRRCAP MSR to determine the number of variable range MTRRs
    /// supported by the processor. This information is used to iterate over all
    /// variable MTRRs in the system.
    ///
    /// # Returns
    /// The number of variable range MTRRs.
    ///
    /// # Reference
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 12.11.1 MTRR Feature Identification
    /// - Figure 12-5. IA32_MTRRCAP Register
    pub fn count() -> usize {
        rdmsr(IA32_MTRRCAP) as usize & 0xFF
    }

    /// Creates an iterator over the MTRR indexes.
    ///
    /// This iterator allows for iterating over all variable range MTRRs in the system,
    /// facilitating access to each MTRR's configuration.
    ///
    /// # Returns
    /// An iterator over the range of MTRR indexes.
    pub fn indexes() -> impl Iterator<Item = MtrrIndex> {
        (0..Self::count() as u8).into_iter().map(|v| MtrrIndex(v))
    }

    /// Retrieves the configuration for a specific MTRR.
    ///
    /// Reads the base and mask MSRs for the MTRR specified by `index` and constructs
    /// an `MtrrItem` representing its configuration.
    ///
    /// # Arguments
    /// * `index` - The index of the MTRR to retrieve.
    ///
    /// # Returns
    /// An `MtrrItem` representing the specified MTRR's configuration.
    pub fn get(index: MtrrIndex) -> MtrrItem {
        let base = rdmsr(Self::ia32_mtrrphys_base(index));
        let mask = rdmsr(Self::ia32_mtrrphys_mask(index));
        MtrrItem::from_raw(base, mask)
    }

    /// Calculates the base MSR address for a given MTRR index.
    ///
    /// # Arguments
    /// * `n` - The MTRR index.
    ///
    /// # Returns
    /// The base MSR address for the MTRR.
    pub fn ia32_mtrrphys_base(n: MtrrIndex) -> u32 {
        IA32_MTRR_PHYSBASE0 + n.0 as u32 * 2
    }

    /// Calculates the mask MSR address for a given MTRR index.
    ///
    /// # Arguments
    /// * `n` - The MTRR index.
    ///
    /// # Returns
    /// The mask MSR address for the MTRR.
    pub fn ia32_mtrrphys_mask(n: MtrrIndex) -> u32 {
        IA32_MTRR_PHYSMASK0 + n.0 as u32 * 2
    }

    pub const fn from_raw(value: u8) -> MemoryType {
        match value {
            0 => MemoryType::Uncacheable,
            1 => MemoryType::WriteCombining,
            4 => MemoryType::WriteThrough,
            5 => MemoryType::WriteProtected,
            6 => MemoryType::WriteBack,
            _ => MemoryType::Uncacheable,
        }
    }
}

/// Represents an index into the array of variable MTRRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MtrrIndex(pub u8);

/// Describes a specific MTRR memory range.
#[derive(Debug, Clone, Copy)]
pub struct MtrrRangeDescriptor {
    /// The base address of the memory range.
    pub base_address: u64,
    /// The end address of the memory range.
    pub end_address: u64,
    /// The memory type associated with this range.
    pub memory_type: MemoryType,
}

/// Represents the configuration of a single MTRR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtrrItem {
    /// The physical base address for this MTRR.
    pub base: PhysicalAddress,
    /// The mask that determines the size and enablement of the MTRR.
    pub mask: u64,
    /// The memory type (caching behavior) of this MTRR.
    pub mem_type: MemoryType,
    /// Flag indicating whether this MTRR is enabled.
    pub is_enabled: bool,
}

impl MtrrItem {
    /// Mask for filtering the relevant address bits, aligning to page size (4 KB).
    const ADDR_MASK: u64 = !0xFFF;

    /// Constructs an MtrrItem from raw MSR values.
    ///
    /// # Arguments
    /// * `base` - The base address read from the IA32_MTRR_PHYSBASE MSR.
    /// * `mask` - The mask read from the IA32_MTRR_PHYSMASK MSR.
    ///
    /// # Returns
    /// A new `MtrrItem` representing the MSR's configuration.
    pub fn from_raw(base: u64, mask: u64) -> Self {
        let mem_type = Mtrr::from_raw(base as u8);
        let is_enabled = (mask & 0x800) != 0;
        Self {
            base: PhysicalAddress::from_pa(base & Self::ADDR_MASK),
            mask: mask & Self::ADDR_MASK,
            mem_type,
            is_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_uses_uncacheable_for_partial_overlap() {
        let mtrr = Mtrr::for_test(
            MemoryType::WriteBack,
            &[MtrrRangeDescriptor {
                base_address: 0x180000,
                end_address: 0x1fffff,
                memory_type: MemoryType::Uncacheable,
            }],
        );

        assert_eq!(mtrr.find(0x000000..0x200000), Some(MemoryType::Uncacheable));
    }
}
