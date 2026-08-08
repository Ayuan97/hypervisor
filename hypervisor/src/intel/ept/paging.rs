//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3 THE EXTENDED PAGE TABLE MECHANISM (EPT)
//! The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
//! When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory) are instead treated as guest-physical addresses
//! Guest-physical addresses are translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.
//!
//! Credits to the work by Satoshi (https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/epts.rs) and Matthias (https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/svm/nested_page_table.rs).

use {
    crate::{
        error::HypervisorError,
        intel::ept::mtrr::{MemoryType, Mtrr},
        utils::addresses::PhysicalAddress,
    },
    alloc::boxed::Box,
    bitfield::bitfield,
    bitflags::bitflags,
    core::ptr::{addr_of, null_mut},
    x86::bits64::paging::{
        pd_index, pdpt_index, pml4_index, pt_index, VAddr, BASE_PAGE_SHIFT, BASE_PAGE_SIZE,
        PAGE_SIZE_ENTRIES,
    },
};

bitflags! {
    /// Represents the different access permissions for an EPT entry.
    #[derive(Debug, Clone, Copy)]
    pub struct AccessType: u8 {
        /// The EPT entry allows read access.
        const READ = 0b001;
        /// The EPT entry allows write access.
        const WRITE = 0b010;
        /// The EPT entry allows execute access.
        const EXECUTE = 0b100;
        /// The EPT entry allows read and write access.
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        /// The EPT entry allows read and execute access.
        const READ_EXECUTE = Self::READ.bits() | Self::EXECUTE.bits();
        /// The EPT entry allows write and execute access.
        const WRITE_EXECUTE = Self::WRITE.bits() | Self::EXECUTE.bits();
        /// The EPT entry allows read, write, and execute access.
        const READ_WRITE_EXECUTE = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}

pub const _512GB: u64 = 512 * 1024 * 1024 * 1024;
pub const _1GB: u64 = 1024 * 1024 * 1024;
pub const _2MB: usize = 2 * 1024 * 1024;
pub const _4KB: usize = 4 * 1024;
const MAX_SPLIT_PTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityLeafKind {
    FullRam,
    NonRam,
    Mixed,
}

/// Represents the entire Extended Page Table structure.
///
/// EPT is a set of nested page tables similar to the standard x86-64 paging mechanism.
/// It consists of 4 levels: PML4, PDPT, PD, and PT.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
#[repr(C, align(4096))]
pub struct Ept {
    /// Page Map Level 4 (PML4) Table.
    pml4: Pml4,
    /// Page Directory Pointer Table (PDPT).
    pdpt: Pdpt,
    /// Array of Page Directory Table (PDT).
    pd: [Pd; 512],
    split_pts: [SplitPt; MAX_SPLIT_PTS],
}

impl Ept {
    /// Creates an identity map for 2MB pages in the Extended Page Tables (EPT).
    ///
    /// Similar to `identity_4kb`, but maps larger 2MB pages for better performance in some scenarios
    ///
    /// # Arguments
    ///
    /// * `access_type`: The type of access allowed for these pages (read, write, execute).
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    pub fn identity_2mb(&mut self, access_type: AccessType) -> Result<(), HypervisorError> {
        log::trace!("Creating identity map for 2MB pages");
        crate::intel::diag_trace::trace("ept: identity_2mb start");

        let mut mtrr = Mtrr::new();

        let ram_known = mtrr.ram_ranges_known();
        if !ram_known {
            crate::intel::diag::set_ept_identity_stats(0, 0, 0, false);
            log::error!("Cannot build EPT identity map without physical RAM ranges");
            return Err(HypervisorError::MemoryTypeResolutionError);
        }

        let mut rwx_pages = 0u64;
        let mut rw_pages = 0u64;
        let mut split_pages = 0u64;
        for pa in (0.._512GB).step_by(_2MB) {
            match self.map_identity_2mb_leaf(pa, access_type, &mut mtrr)? {
                IdentityLeafKind::FullRam => rwx_pages += 1,
                IdentityLeafKind::NonRam => rw_pages += 1,
                IdentityLeafKind::Mixed => split_pages += 1,
            }
        }

        // Persist counts for postmortem (cpuid_ping CTL / future log).
        crate::intel::diag::set_ept_identity_stats(rwx_pages, rw_pages, split_pages, ram_known);
        crate::intel::diag::set_boot_stage(212);
        log::info!(
            "EPT identity: ram_2mb={} non_ram_2mb={} split_2mb={} ram_ranges_known={}",
            rwx_pages,
            rw_pages,
            split_pages,
            ram_known
        );
        crate::intel::diag_trace::trace("ept: identity_2mb done");
        Ok(())
    }

    fn map_identity_2mb_leaf(
        &mut self,
        pa: u64,
        access_type: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<IdentityLeafKind, HypervisorError> {
        if !mtrr.ram_ranges_known() {
            return Err(HypervisorError::MemoryTypeResolutionError);
        }

        let range = pa..pa.saturating_add(_2MB as u64);
        if mtrr.range_is_backed_by_ram(range.clone()) {
            if mtrr.uniform_memory_type(range).is_some() {
                self.map_2mb(pa, pa, access_type, mtrr)?;
                return Ok(IdentityLeafKind::FullRam);
            }
            self.map_mixed_identity_2mb(pa, access_type, mtrr)?;
            return Ok(IdentityLeafKind::Mixed);
        }

        let non_executable = access_type & !AccessType::EXECUTE;
        if !mtrr.range_overlaps_ram(range) {
            self.map_2mb(pa, pa, non_executable, mtrr)?;
            return Ok(IdentityLeafKind::NonRam);
        }

        self.map_mixed_identity_2mb(pa, access_type, mtrr)?;
        Ok(IdentityLeafKind::Mixed)
    }

    /// Maps a RAM/MMIO or MTRR-type boundary at 4KB granularity. The PT is
    /// fully initialized before the PDE pointer is published, so no EPT walk
    /// can observe a partially populated table.
    fn map_mixed_identity_2mb(
        &mut self,
        pa: u64,
        access_type: AccessType,
        mtrr: &Mtrr,
    ) -> Result<(), HypervisorError> {
        self.map_pml4(pa, access_type)?;
        self.map_pdpt(pa, access_type)?;

        let address = VAddr::from(pa);
        let pdpt_index = pdpt_index(address);
        let pd_index = pd_index(address);
        if self.pd[pdpt_index].0.entries[pd_index].readable()
            || self.find_split_pt(pdpt_index, pd_index).is_some()
        {
            return Err(HypervisorError::AlreadySplitError);
        }

        let pt = allocate_pt()?;
        for index in 0..PAGE_SIZE_ENTRIES {
            let page_pa = pa + (index * BASE_PAGE_SIZE) as u64;
            let page_range = page_pa..page_pa + BASE_PAGE_SIZE as u64;
            let page_access = if mtrr.range_is_backed_by_ram(page_range.clone()) {
                access_type
            } else {
                access_type & !AccessType::EXECUTE
            };
            let memory_type = mtrr.find(page_range).unwrap_or(MemoryType::Uncacheable);
            let entry = unsafe { &mut (*pt).0.entries[index] };
            entry.0 = page_access.bits() as u64
                | ((memory_type as u64) << 3)
                | ((page_pa >> BASE_PAGE_SHIFT) << 12);
        }

        let pt_pa = table_pa_from_va(pt as u64);
        if pt_pa == 0 {
            unsafe {
                free_pt(pt);
            }
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }
        if self.record_split_pt(pdpt_index, pd_index, pt).is_err() {
            unsafe {
                free_pt(pt);
            }
            return Err(HypervisorError::OutOfMemory);
        }

        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];
        pd_entry.0 =
            AccessType::READ_WRITE_EXECUTE.bits() as u64 | ((pt_pa >> BASE_PAGE_SHIFT) << 12);
        Ok(())
    }

    /// Creates an identity map for 4KB pages in the Extended Page Tables (EPT).
    ///
    /// An identity map means every guest physical address maps directly to the same host physical address.
    ///
    /// # Arguments
    ///
    /// * `access_type`: The type of access allowed for these pages (read, write, execute).
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    pub fn identity_4kb(&mut self, _access_type: AccessType) -> Result<(), HypervisorError> {
        log::error!("Full 512GB 4KB identity EPT is not supported by the bounded split table");
        Err(HypervisorError::OutOfMemory)
    }

    /// Maps a single 2MB page in the EPT.
    ///
    /// # Arguments
    ///
    /// * `guest_pa`: The guest physical address to map.
    /// * `host_pa`: The host physical address to map to.
    /// * `access_type`: The type of access allowed for this page (read, write, execute).
    /// * `mtrr`: The Memory Type Range Registers (MTRR) to use for this page.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    pub fn map_2mb(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access_type: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<(), HypervisorError> {
        self.map_pml4(guest_pa, access_type)?;
        self.map_pdpt(guest_pa, access_type)?;
        self.map_pde(guest_pa, host_pa, access_type, mtrr)?;

        Ok(())
    }

    /// Maps a single 4KB page in the EPT.
    ///
    /// # Arguments
    /// * `guest_pa`: The guest physical address to map.
    /// * `host_pa`: The host physical address to map to.
    /// * `access_type`: The type of access allowed for this page (read, write, execute).
    /// * `mtrr`: The Memory Type Range Registers (MTRR) to use for this page.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    pub fn map_4kb(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access_type: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<(), HypervisorError> {
        self.map_pml4(guest_pa, access_type)?;
        self.map_pdpt(guest_pa, access_type)?;
        self.map_pdt(guest_pa, access_type)?;
        self.map_pt(guest_pa, host_pa, access_type, mtrr)?;

        Ok(())
    }

    /// Updates the PML4 entry corresponding to the provided guest physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_pa`: The guest physical address whose corresponding PML4 entry will be updated.
    /// * `access_type`: The type of access allowed for the region covered by this PML4 entry.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    fn map_pml4(&mut self, guest_pa: u64, _access_type: AccessType) -> Result<(), HypervisorError> {
        let pml4_index = pml4_index(VAddr::from(guest_pa));
        let pml4_entry = &mut self.pml4.0.entries[pml4_index];

        // Intermediate EPT pointers must always be R/W/X. Leaf PDE/PT entries
        // enforce the real policy (e.g. MMIO = RW-only). If we stamped a parent
        // from the *first* child access_type and that child was MMIO (no X),
        // later RAM under the same PML4/PDPT would fail instruction fetch →
        // exit storm / 0x101 after VMLAUNCH (boot_stage stuck at 700).
        if !pml4_entry.readable() {
            pml4_entry.set_readable(true);
            pml4_entry.set_writable(true);
            pml4_entry.set_executable(true);
            pml4_entry.set_pfn(table_pa_from_va(addr_of!(self.pdpt) as u64) >> BASE_PAGE_SHIFT);
        } else {
            pml4_entry.set_writable(true);
            pml4_entry.set_executable(true);
        }

        Ok(())
    }

    /// Updates the PDPT entry corresponding to the provided guest physical address.
    ///
    /// # Arguments
    /// * `guest_pa`: The guest physical address whose corresponding PDPT entry will be updated.
    /// * `access_type`: Unused for intermediate entries; leaf policy is on the PDE.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    fn map_pdpt(&mut self, guest_pa: u64, _access_type: AccessType) -> Result<(), HypervisorError> {
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pdpt_entry = &mut self.pdpt.0.entries[pdpt_index];

        // Same rule as map_pml4: parent walks stay fully privileged.
        if !pdpt_entry.readable() {
            pdpt_entry.set_readable(true);
            pdpt_entry.set_writable(true);
            pdpt_entry.set_executable(true);
            pdpt_entry
                .set_pfn(table_pa_from_va(addr_of!(self.pd[pdpt_index]) as u64) >> BASE_PAGE_SHIFT);
        } else {
            pdpt_entry.set_writable(true);
            pdpt_entry.set_executable(true);
        }

        Ok(())
    }

    /// Updates the PDT entry corresponding to the provided guest physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_pa`: The guest physical address whose corresponding PDT entry will be updated.
    /// * `access_type`: The type of access allowed for the region covered by this PDT entry.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    fn map_pdt(&mut self, guest_pa: u64, _access_type: AccessType) -> Result<(), HypervisorError> {
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pd_index = pd_index(VAddr::from(guest_pa));

        if self.pd[pdpt_index].0.entries[pd_index].large() {
            return Err(HypervisorError::AlreadySplitError);
        }

        if self.find_split_pt(pdpt_index, pd_index).is_some() {
            return Ok(());
        }

        let pt = allocate_pt()?;
        if self.record_split_pt(pdpt_index, pd_index, pt).is_err() {
            unsafe {
                free_pt(pt);
            }
            return Err(HypervisorError::OutOfMemory);
        }

        let pt_pfn = table_pa_from_va(pt as u64) >> BASE_PAGE_SHIFT;
        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];
        // This is a non-leaf entry. Permissions belong to the PTEs; restricting
        // this pointer from its first child would also restrict every sibling.
        pd_entry.0 = AccessType::READ_WRITE_EXECUTE.bits() as u64 | (pt_pfn << 12);

        Ok(())
    }

    /// Updates the PD entry corresponding to the provided guest physical address for 2MB page mapping.
    ///
    /// # Arguments
    /// * `guest_pa`: The guest physical address whose corresponding PD entry will be updated.
    /// * `host_pa`: The host physical address to map to.
    /// * `access_type`: The type of access allowed for this 2MB page.
    /// * `mtrr`: The Memory Type Range Registers (MTRR) to use for this page.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    fn map_pde(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access_type: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<(), HypervisorError> {
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pd_index = pd_index(VAddr::from(guest_pa));
        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];

        if !pd_entry.readable() {
            // Single store: multi-step bitfield writes leave reserved/transient
            // patterns visible if another CPU walks EPT mid-update.
            let mem_type = mtrr_memory_type_for_2mb(host_pa, mtrr) as u64;
            let pfn = host_pa >> BASE_PAGE_SHIFT;
            pd_entry.0 = (access_type.bits() as u64)
                | ((mem_type & 0x7) << 3)
                | (1u64 << 7) // large page
                | (pfn << 12);
        } else {
            log::warn!(
                "Attempted to map an already-mapped 2MB page: {:x}",
                guest_pa
            );
        }

        Ok(())
    }

    /// Updates the PT entry corresponding to the provided guest physical address for 4KB page mapping.
    ///
    /// # Arguments
    /// * `guest_pa`: The guest physical address whose corresponding PT entry will be updated.
    /// * `host_pa`: The host physical address to map to.
    /// * `access_type`: The type of access allowed for this 4KB page.
    /// * `mtrr`: The Memory Type Range Registers (MTRR) to use for this page.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    fn map_pt(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access_type: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<(), HypervisorError> {
        self.map_split_4kb(
            guest_pa,
            host_pa,
            access_type,
            mtrr.find(host_pa..host_pa + BASE_PAGE_SIZE as u64)
                .unwrap_or(MemoryType::WriteBack),
        )
    }

    /// Modifies the access permissions for a page within the extended page table (EPT).
    ///
    /// This function adjusts the permissions of either a 2MB or a 4KB page based on its alignment.
    /// It is the responsibility of the caller to ensure that the `guest_pa` is aligned to the size
    /// of the page they intend to modify.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - Guest physical address of the page whose permissions are to be changed.
    /// * `access_type` - The new access permissions to set for the page.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    pub fn change_page_flags(
        &mut self,
        guest_pa: u64,
        access_type: AccessType,
    ) -> Result<(), HypervisorError> {
        let guest_pa = VAddr::from(guest_pa);

        if !guest_pa.is_large_page_aligned() && !guest_pa.is_base_page_aligned() {
            log::error!("Page is not aligned: {:#x}", guest_pa);
            return Err(HypervisorError::UnalignedAddressError);
        }

        self.set_page_access(guest_pa.as_u64(), access_type)
    }

    /// Splits a large 2MB page into 512 smaller 4KB pages for a given guest physical address.
    ///
    /// This is necessary to apply more granular hooks and reduce the number of
    /// page faults that occur when the guest tries to access a page that is hooked.
    ///
    /// # Arguments
    ///
    /// * `guest_pa`: The guest physical address within the 2MB page that needs to be split.
    /// * `access_type`: The type of access allowed for the newly created 4KB pages.
    ///
    /// # Returns
    ///
    /// A `Result<(), HypervisorError>` indicating if the operation was successful.
    pub fn split_2mb_to_4kb(
        &mut self,
        guest_pa: u64,
        access_type: AccessType,
    ) -> Result<(), HypervisorError> {
        let guest_pa = VAddr::from(guest_pa);
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let (host_base, memory_type) = {
            let pd_entry = &self.pd[pdpt_index].0.entries[pd_index];
            if !pd_entry.readable() {
                return Err(HypervisorError::InvalidPdEntry);
            }
            if !pd_entry.large() {
                return Err(HypervisorError::PageAlreadySplit);
            }
            (pd_entry.pfn() << BASE_PAGE_SHIFT, pd_entry.memory_type())
        };
        let pt = allocate_pt()?;

        for i in 0..PAGE_SIZE_ENTRIES {
            let pa = host_base + (i * BASE_PAGE_SIZE) as u64;
            let entry = unsafe { &mut (*pt).0.entries[i] };
            set_entry_access(entry, access_type);
            entry.set_memory_type(memory_type);
            entry.set_large(false);
            entry.set_pfn(pa >> BASE_PAGE_SHIFT);
        }

        if self.record_split_pt(pdpt_index, pd_index, pt).is_err() {
            unsafe {
                free_pt(pt);
            }
            return Err(HypervisorError::OutOfMemory);
        }

        let pt_pfn = table_pa_from_va(pt as u64) >> BASE_PAGE_SHIFT;
        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];
        pd_entry.0 = access_type.bits() as u64 | (pt_pfn << 12);

        Ok(())
    }

    /// Remaps the given guest physical address and changes it to the given host physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_pa`: The guest physical address to remap.
    /// * `host_pa`: The host physical address to remap to.
    /// * `access_type`: The type of access allowed for this page (read, write, execute).
    /// * `mtrr`: The Memory Type Range Registers (MTRR) to use for this page.
    /// Credits: Jess / jessiep_
    pub fn remap_page(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access_type: AccessType,
    ) -> Result<(), HypervisorError> {
        self.map_split_4kb(guest_pa, host_pa, access_type, memory_type_for_4kb(host_pa))
    }

    pub fn set_page_access(
        &mut self,
        guest_pa: u64,
        access_type: AccessType,
    ) -> Result<(), HypervisorError> {
        let guest_pa = VAddr::from(guest_pa);

        if !guest_pa.is_large_page_aligned() && !guest_pa.is_base_page_aligned() {
            return Err(HypervisorError::UnalignedAddressError);
        }

        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);
        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];

        if pd_entry.large() {
            set_entry_access(pd_entry, access_type);
            return Ok(());
        }

        let Some(pt) = self.find_split_pt_mut(pdpt_index, pd_index) else {
            return Err(HypervisorError::InvalidPml1Entry);
        };

        set_entry_access(&mut pt.0.entries[pt_index], access_type);
        Ok(())
    }

    /// Unmaps a 2MB page by clearing the corresponding page directory entry.
    ///
    /// This function clears the entry, effectively removing any mapping for the 2MB page.
    /// It's used when transitioning a region of memory from a single large page to multiple smaller pages or simply freeing the page.
    ///
    /// # Arguments
    ///
    /// * `entry`: Mutable reference to the page directory entry to unmap.
    pub fn unmap_2mb(entry: &mut Entry) {
        if !entry.readable() {
            return;
        }

        // Single store: avoids transient reserved states visible to other CPUs.
        entry.0 = 0;
    }

    /// Unmaps a 4KB page, typically involved in deconstructing finer-grained page tables.
    ///
    /// This function wraps the unmap_2mb function, as the actual unmap logic is similar.
    /// It's used for unmap operations specifically targeting 4KB pages.
    ///
    /// # Arguments
    ///
    /// * `entry`: Mutable reference to the page directory entry of the 4KB page to unmap.
    #[allow(dead_code)]
    fn unmap_4kb(entry: &mut Entry) {
        // Delegate to the unmap_2mb function as the unmap logic is the same.
        Self::unmap_2mb(entry);
    }

    /// Creates an Extended Page Table Pointer (EPTP) with a Write-Back memory type and a 4-level page walk.
    ///
    /// This function is used in the setup of Intel VT-x virtualization, specifically for configuring the EPT.
    /// It encodes the provided physical base address of the EPT PML4 table into the EPTP format, setting
    /// the memory type to Write-Back and indicating a 4-level page walk.
    ///
    /// # Returns
    /// A `Result<u64, HypervisorError>` containing the configured EPTP value. Returns an error if
    /// the base address is not properly aligned.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 28.2.6 EPT Paging-Structure Entries
    pub fn create_eptp_with_wb_and_4lvl_walk(&self) -> Result<u64, HypervisorError> {
        // Get the virtual address of the PML4 table for EPT.
        let addr = addr_of!(self.pml4) as u64;

        // Get the physical address of the PML4 table for EPT.
        let ept_pml4_base_addr = PhysicalAddress::pa_from_va(addr);

        // Represents the EPT page walk length for Intel VT-x, specifically for a 4-level page walk.
        // The value is 3 (encoded as '3 << 3' in EPTP) because the EPTP encoding requires "number of levels minus one".
        const EPT_PAGE_WALK_LENGTH_4: u64 = 3 << 3;

        // Represents the memory type setting for Write-Back (WB) in the EPTP.
        const EPT_MEMORY_TYPE_WB: u64 = MemoryType::WriteBack as u64;

        // Reject null / unaligned PML4 PA. Note: u64::trailing_zeros(0) == 64,
        // so a zero address would otherwise pass the alignment check and yield
        // EPTP = walk_len|WB with a null table → instant EPT misconfig storm.
        if ept_pml4_base_addr != 0 && ept_pml4_base_addr.trailing_zeros() >= 12 {
            Ok(ept_pml4_base_addr | EPT_PAGE_WALK_LENGTH_4 | EPT_MEMORY_TYPE_WB)
        } else {
            Err(HypervisorError::InvalidEptPml4BaseAddress)
        }
    }

    fn find_split_pt(&self, pdpt_index: usize, pd_index: usize) -> Option<&Pt> {
        self.split_pts
            .iter()
            .find(|slot| slot.matches(pdpt_index, pd_index))
            .map(|slot| unsafe { &*slot.pt })
    }

    fn find_split_pt_mut(&mut self, pdpt_index: usize, pd_index: usize) -> Option<&mut Pt> {
        self.split_pts
            .iter_mut()
            .find(|slot| slot.matches(pdpt_index, pd_index))
            .map(|slot| unsafe { &mut *slot.pt })
    }

    fn map_split_4kb(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access_type: AccessType,
        memory_type: MemoryType,
    ) -> Result<(), HypervisorError> {
        let guest_pa = VAddr::from(guest_pa);
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);
        let Some(pt) = self.find_split_pt_mut(pdpt_index, pd_index) else {
            return Err(HypervisorError::InvalidPml1Entry);
        };

        let pt_entry = &mut pt.0.entries[pt_index];
        pt_entry.0 = access_type.bits() as u64
            | ((memory_type as u64) << 3)
            | ((host_pa >> BASE_PAGE_SHIFT) << 12);

        Ok(())
    }

    fn record_split_pt(
        &mut self,
        pdpt_index: usize,
        pd_index: usize,
        pt: *mut Pt,
    ) -> Result<(), ()> {
        if self.find_split_pt(pdpt_index, pd_index).is_some() {
            return Ok(());
        }

        let Some(slot) = self.split_pts.iter_mut().find(|slot| slot.pt.is_null()) else {
            return Err(());
        };

        slot.pdpt_index = pdpt_index as u16;
        slot.pd_index = pd_index as u16;
        slot.pt = pt;
        Ok(())
    }
}

impl Drop for Ept {
    fn drop(&mut self) {
        for slot in self.split_pts.iter_mut() {
            if !slot.pt.is_null() {
                unsafe {
                    free_pt(slot.pt);
                }
                slot.pt = null_mut();
            }
        }
    }
}

/// Represents an EPT PML4 Entry (PML4E) that references a Page-Directory-Pointer Table.
///
/// PML4 is the top level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-1. Format of an EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
#[derive(Debug, Clone, Copy)]
struct Pml4(Table);

/// Represents an EPT Page-Directory-Pointer-Table Entry (PDPTE) that references an EPT Page Directory.
///
/// PDPTEs are part of the second level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-3. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

/// Represents an EPT Page-Directory Entry (PDE) that references an EPT Page Table.
///
/// PDEs are part of the third level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-5. Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table
#[derive(Debug, Clone, Copy)]
struct Pd(Table);

/// Represents an EPT Page-Table Entry (PTE) that maps a 4-KByte Page.
///
/// PTEs are the lowest level in the EPT paging hierarchy and are used to map individual
/// pages to guest-physical addresses.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Format of an EPT Page-Table Entry that Maps a 4-KByte Page
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct Pt(Table);

#[repr(C)]
#[derive(Clone, Copy)]
struct SplitPt {
    pdpt_index: u16,
    pd_index: u16,
    pt: *mut Pt,
}

impl SplitPt {
    fn matches(&self, pdpt_index: usize, pd_index: usize) -> bool {
        !self.pt.is_null()
            && self.pdpt_index as usize == pdpt_index
            && self.pd_index as usize == pd_index
    }
}

/// General struct to represent a table in the EPT paging structure.
///
/// This struct is used as a basis for PML4, PDPT, PD, and PT. It contains an array of entries
/// where each entry can represent different levels of the EPT hierarchy.
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
struct Table {
    entries: [Entry; 512],
}

bitfield! {
    /// Represents an Extended Page Table Entry (EPT Entry).
    ///
    /// EPT entries are used in Intel VT-x virtualization to manage memory access
    /// permissions and address mapping for virtual machines.
    ///
    /// # Fields
    ///
    /// * `readable` - If set, the memory region can be read.
    /// * `writable` - If set, the memory region can be written to.
    /// * `executable` - If set, code can be executed from the memory region.
    /// * `memory_type` - The memory type (e.g., WriteBack, Uncacheable).
    /// * `large` - If set, this entry maps a large page.
    /// * `pfn` - The Page Frame Number, indicating the physical address.
    /// * `verify_guest_paging` - Additional flag for guest paging verification.
    /// * `paging_write_access` - Additional flag for paging write access.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
    #[derive(Clone, Copy)]
    pub struct Entry(u64);
    impl Debug;

    // Flag definitions for an EPT entry.
    pub readable, set_readable: 0;
    pub writable, set_writable: 1;
    pub executable, set_executable: 2;
    pub memory_type, set_memory_type: 5, 3;
    pub large, set_large: 7;
    pub pfn, set_pfn: 51, 12;
    pub verify_guest_paging, set_verify_guest_paging: 57;
    pub paging_write_access, set_paging_write_access: 58;
}

fn set_entry_access(entry: &mut Entry, access_type: AccessType) {
    // Single store: avoids transient reserved bit patterns (e.g. writable
    // without readable) that cause EPT misconfiguration on other CPUs.
    entry.0 = (entry.0 & !0b111u64) | access_type.bits() as u64;
}

#[cfg(not(test))]
fn table_pa_from_va(va: u64) -> u64 {
    PhysicalAddress::pa_from_va(va)
}

#[cfg(test)]
fn table_pa_from_va(va: u64) -> u64 {
    va
}

#[cfg(not(test))]
fn allocate_pt() -> Result<*mut Pt, HypervisorError> {
    let pt = unsafe {
        Box::<Pt, crate::utils::alloc::PhysicalAllocator>::try_new_zeroed_in(
            crate::utils::alloc::PhysicalAllocator,
        )?
        .assume_init()
    };
    let (pt, _) = Box::into_raw_with_allocator(pt);
    Ok(pt)
}

#[cfg(test)]
fn allocate_pt() -> Result<*mut Pt, HypervisorError> {
    let pt = unsafe { Box::<Pt>::new_zeroed().assume_init() };
    Ok(Box::into_raw(pt))
}

#[cfg(not(test))]
unsafe fn free_pt(pt: *mut Pt) {
    drop(Box::from_raw_in(pt, crate::utils::alloc::PhysicalAllocator));
}

#[cfg(test)]
unsafe fn free_pt(pt: *mut Pt) {
    drop(Box::from_raw(pt));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::ept::mtrr::{MemoryType, MtrrRangeDescriptor, PhysicalMemoryRange};
    use alloc::{boxed::Box, vec::Vec};

    fn large_mapped_ept(guest_pa: u64, host_pa: u64) -> Box<Ept> {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let mut mtrr = Mtrr::for_test_with_ram_ranges(
            MemoryType::WriteBack,
            &[],
            &[PhysicalMemoryRange {
                base_address: host_pa,
                end_address: host_pa + _2MB as u64,
            }],
        );
        ept.map_pde(guest_pa, host_pa, AccessType::READ_WRITE_EXECUTE, &mut mtrr)
            .unwrap();
        ept
    }

    fn split_pt_for_test(ept: &Ept, pdpt_index: usize, pd_index: usize) -> &Pt {
        let pd_entry = &ept.pd[pdpt_index].0.entries[pd_index];
        assert!(!pd_entry.large());
        assert_ne!(pd_entry.pfn(), 0);
        unsafe { &*((pd_entry.pfn() << BASE_PAGE_SHIFT) as *const Pt) }
    }

    #[test]
    fn memory_type_comes_from_matching_mtrr_range() {
        let mtrr = Mtrr::for_test_with_ram_ranges(
            MemoryType::WriteBack,
            &[MtrrRangeDescriptor {
                base_address: 0x1000_0000,
                end_address: 0x101F_FFFF,
                memory_type: MemoryType::Uncacheable,
            }],
            &[PhysicalMemoryRange {
                base_address: 0x1000_0000,
                end_address: 0x1020_0000,
            }],
        );

        assert_eq!(
            mtrr_memory_type_for_2mb(0x1000_0000, &mtrr),
            MemoryType::Uncacheable
        );
    }

    #[test]
    fn memory_type_falls_back_to_default_mtrr_type() {
        let mtrr = Mtrr::for_test_with_ram_ranges(
            MemoryType::WriteCombining,
            &[],
            &[PhysicalMemoryRange {
                base_address: 0x2000_0000,
                end_address: 0x2020_0000,
            }],
        );

        assert_eq!(
            mtrr_memory_type_for_2mb(0x2000_0000, &mtrr),
            MemoryType::WriteCombining
        );
    }

    #[test]
    fn split_2mb_page_creates_4kb_entries_with_original_mapping() {
        let mut ept = large_mapped_ept(0, 0);

        ept.split_2mb_to_4kb(0x1234, AccessType::READ_WRITE_EXECUTE)
            .unwrap();

        let pd_entry = &ept.pd[0].0.entries[0];
        assert!(!pd_entry.large());
        assert!(pd_entry.readable());
        assert!(pd_entry.writable());
        assert!(pd_entry.executable());

        let pt = split_pt_for_test(&ept, 0, 0);
        let first_entry = pt.0.entries[0];
        assert!(first_entry.readable());
        assert!(first_entry.writable());
        assert!(first_entry.executable());
        assert_eq!(first_entry.memory_type(), MemoryType::WriteBack as u64);
        assert_eq!(first_entry.pfn(), 0);

        let last_entry = pt.0.entries[511];
        assert_eq!(last_entry.pfn(), ((_2MB - _4KB) as u64) >> BASE_PAGE_SHIFT);
    }

    #[test]
    fn remap_page_updates_one_split_4kb_mapping() {
        let mut ept = large_mapped_ept(0, 0);
        ept.split_2mb_to_4kb(0, AccessType::READ_WRITE_EXECUTE)
            .unwrap();

        ept.remap_page(0x3000, 0xABC0_0000, AccessType::EXECUTE)
            .unwrap();

        let pt = split_pt_for_test(&ept, 0, 0);
        let remapped = pt.0.entries[3];
        assert!(!remapped.readable());
        assert!(!remapped.writable());
        assert!(remapped.executable());
        assert_eq!(remapped.pfn(), 0xABC0_0000 >> BASE_PAGE_SHIFT);
    }

    #[test]
    fn set_page_access_updates_one_split_4kb_entry() {
        let mut ept = large_mapped_ept(0, 0);
        ept.split_2mb_to_4kb(0, AccessType::READ_WRITE_EXECUTE)
            .unwrap();

        ept.set_page_access(0x2000, AccessType::empty()).unwrap();

        let pt = split_pt_for_test(&ept, 0, 0);
        let hidden = pt.0.entries[2];
        assert!(!hidden.readable());
        assert!(!hidden.writable());
        assert!(!hidden.executable());

        let neighbor = pt.0.entries[1];
        assert!(neighbor.readable());
        assert!(neighbor.writable());
        assert!(neighbor.executable());
    }

    #[test]
    fn identity_leaf_keeps_full_ram_as_large_rwx() {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let mut mtrr = Mtrr::for_test_with_ram_ranges(
            MemoryType::WriteBack,
            &[],
            &[PhysicalMemoryRange {
                base_address: 0,
                end_address: _2MB as u64,
            }],
        );

        assert_eq!(
            ept.map_identity_2mb_leaf(0, AccessType::READ_WRITE_EXECUTE, &mut mtrr)
                .unwrap(),
            IdentityLeafKind::FullRam
        );
        let entry = ept.pd[0].0.entries[0];
        assert!(entry.large());
        assert!(entry.readable() && entry.writable() && entry.executable());
        assert_eq!(entry.memory_type(), MemoryType::WriteBack as u64);
    }

    #[test]
    fn identity_leaf_keeps_non_ram_as_large_rw_uc() {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let mut mtrr = Mtrr::for_test_with_ram_ranges(MemoryType::WriteBack, &[], &[]);

        assert_eq!(
            ept.map_identity_2mb_leaf(0, AccessType::READ_WRITE_EXECUTE, &mut mtrr)
                .unwrap(),
            IdentityLeafKind::NonRam
        );
        let entry = ept.pd[0].0.entries[0];
        assert!(entry.large());
        assert!(entry.readable() && entry.writable() && !entry.executable());
        assert_eq!(entry.memory_type(), MemoryType::Uncacheable as u64);
    }

    #[test]
    fn identity_leaf_splits_ram_head_from_hole_tail() {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let mut mtrr = Mtrr::for_test_with_ram_ranges(
            MemoryType::WriteBack,
            &[],
            &[PhysicalMemoryRange {
                base_address: 0,
                end_address: BASE_PAGE_SIZE as u64,
            }],
        );

        assert_eq!(
            ept.map_identity_2mb_leaf(0, AccessType::READ_WRITE_EXECUTE, &mut mtrr)
                .unwrap(),
            IdentityLeafKind::Mixed
        );
        let parent = ept.pd[0].0.entries[0];
        assert!(!parent.large());
        assert!(parent.readable() && parent.writable() && parent.executable());
        let pt = split_pt_for_test(&ept, 0, 0);
        let ram = pt.0.entries[0];
        let hole = pt.0.entries[1];
        assert!(ram.executable());
        assert_eq!(ram.memory_type(), MemoryType::WriteBack as u64);
        assert!(!hole.executable());
        assert_eq!(hole.memory_type(), MemoryType::Uncacheable as u64);
    }

    #[test]
    fn identity_leaf_splits_hole_head_from_ram_tail() {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let last_page = (_2MB - _4KB) as u64;
        let mut mtrr = Mtrr::for_test_with_ram_ranges(
            MemoryType::WriteBack,
            &[],
            &[PhysicalMemoryRange {
                base_address: last_page,
                end_address: _2MB as u64,
            }],
        );

        assert_eq!(
            ept.map_identity_2mb_leaf(0, AccessType::READ_WRITE_EXECUTE, &mut mtrr)
                .unwrap(),
            IdentityLeafKind::Mixed
        );
        let parent = ept.pd[0].0.entries[0];
        assert!(!parent.large());
        assert!(parent.executable());
        let pt = split_pt_for_test(&ept, 0, 0);
        assert!(!pt.0.entries[0].executable());
        assert!(pt.0.entries[511].executable());
        assert_eq!(pt.0.entries[511].pfn(), last_page >> BASE_PAGE_SHIFT);
    }

    #[test]
    fn mixed_ram_page_preserves_explicit_uc_type() {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let mut mtrr = Mtrr::for_test_with_ram_ranges(
            MemoryType::WriteBack,
            &[MtrrRangeDescriptor {
                base_address: 0,
                end_address: (BASE_PAGE_SIZE - 1) as u64,
                memory_type: MemoryType::Uncacheable,
            }],
            &[PhysicalMemoryRange {
                base_address: 0,
                end_address: BASE_PAGE_SIZE as u64,
            }],
        );

        ept.map_identity_2mb_leaf(0, AccessType::READ_WRITE_EXECUTE, &mut mtrr)
            .unwrap();
        let pt = split_pt_for_test(&ept, 0, 0);
        assert!(pt.0.entries[0].executable());
        assert_eq!(
            pt.0.entries[0].memory_type(),
            MemoryType::Uncacheable as u64
        );
    }

    #[test]
    fn full_ram_leaf_with_internal_mtrr_boundary_is_split() {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let mut mtrr = Mtrr::for_test_with_ram_ranges(
            MemoryType::WriteBack,
            &[MtrrRangeDescriptor {
                base_address: BASE_PAGE_SIZE as u64,
                end_address: (2 * BASE_PAGE_SIZE - 1) as u64,
                memory_type: MemoryType::WriteCombining,
            }],
            &[PhysicalMemoryRange {
                base_address: 0,
                end_address: _2MB as u64,
            }],
        );

        assert_eq!(
            ept.map_identity_2mb_leaf(0, AccessType::READ_WRITE_EXECUTE, &mut mtrr)
                .unwrap(),
            IdentityLeafKind::Mixed
        );
        let parent = ept.pd[0].0.entries[0];
        assert!(!parent.large());
        assert!(parent.readable() && parent.writable() && parent.executable());

        let pt = split_pt_for_test(&ept, 0, 0);
        assert_eq!(pt.0.entries[0].memory_type(), MemoryType::WriteBack as u64);
        assert_eq!(
            pt.0.entries[1].memory_type(),
            MemoryType::WriteCombining as u64
        );
        assert_eq!(pt.0.entries[2].memory_type(), MemoryType::WriteBack as u64);
        assert!(pt.0.entries[0].executable());
        assert!(pt.0.entries[1].executable());
        assert!(pt.0.entries[2].executable());
    }

    #[test]
    fn identity_leaf_129th_split_slot_does_not_publish_pde() {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let ram_ranges: Vec<PhysicalMemoryRange> = (0..=MAX_SPLIT_PTS)
            .map(|index| {
                let base = index as u64 * _2MB as u64;
                PhysicalMemoryRange {
                    base_address: base,
                    end_address: base + BASE_PAGE_SIZE as u64,
                }
            })
            .collect();
        let mut mtrr = Mtrr::for_test_with_ram_ranges(MemoryType::WriteBack, &[], &ram_ranges);

        for index in 0..MAX_SPLIT_PTS {
            let pa = index as u64 * _2MB as u64;
            assert_eq!(
                ept.map_identity_2mb_leaf(pa, AccessType::READ_WRITE_EXECUTE, &mut mtrr)
                    .unwrap(),
                IdentityLeafKind::Mixed
            );
        }

        let rejected_pa = MAX_SPLIT_PTS as u64 * _2MB as u64;
        assert!(matches!(
            ept.map_identity_2mb_leaf(rejected_pa, AccessType::READ_WRITE_EXECUTE, &mut mtrr),
            Err(HypervisorError::OutOfMemory)
        ));
        let rejected_address = VAddr::from(rejected_pa);
        let rejected_pdpt = pdpt_index(rejected_address);
        let rejected_pd = pd_index(rejected_address);
        assert_eq!(ept.pd[rejected_pdpt].0.entries[rejected_pd].0, 0);
        assert!(ept.find_split_pt(rejected_pdpt, rejected_pd).is_none());
    }

    #[test]
    fn identity_leaf_rejects_unknown_ram_map_without_publishing_entry() {
        let mut ept = unsafe { Box::<Ept>::new_zeroed().assume_init() };
        let mut mtrr = Mtrr::for_test(MemoryType::WriteBack, &[]);

        assert!(matches!(
            ept.map_identity_2mb_leaf(0, AccessType::READ_WRITE_EXECUTE, &mut mtrr),
            Err(HypervisorError::MemoryTypeResolutionError)
        ));
        assert_eq!(ept.pd[0].0.entries[0].0, 0);
    }
}

fn mtrr_memory_type_for_2mb(host_pa: u64, mtrr: &Mtrr) -> MemoryType {
    let end = host_pa.saturating_add(_2MB as u64);
    mtrr.find(host_pa..end).unwrap_or(MemoryType::Uncacheable)
}

#[cfg(not(test))]
fn memory_type_for_4kb(host_pa: u64) -> MemoryType {
    let mtrr = Mtrr::new();
    mtrr.find(host_pa..host_pa + BASE_PAGE_SIZE as u64)
        .unwrap_or(MemoryType::WriteBack)
}

#[cfg(test)]
fn memory_type_for_4kb(_host_pa: u64) -> MemoryType {
    MemoryType::WriteBack
}
