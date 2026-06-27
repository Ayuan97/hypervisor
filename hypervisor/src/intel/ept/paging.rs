// EPT page table structures: PML4, PDPT, PD, PT
// 4-level translation: GPA → HPA
//
// EPT entry format (64-bit):
//   bit 0: Read access
//   bit 1: Write access
//   bit 2: Execute access
//   bit 3-5: Memory type (from MTRRs)
//   bit 7: Large page (1GB or 2MB)
//   bit 12-51: Physical address of next level / final page
//
// Reference: matrix-rs/hypervisor/src/intel/ept/paging.rs
