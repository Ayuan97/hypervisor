pub mod paging;
pub mod hooks;

// EPT (Extended Page Tables) management
//
// Key operations:
// 1. Build identity map: GPA == HPA for all physical memory
// 2. Split 2MB pages to 4KB for fine-grained hook control
// 3. Swap page permissions for read/execute separation
//
// Reference: matrix-rs/hypervisor/src/intel/ept/
// Intel SDM Vol.3 Chapter 28 - VMX Support for Address Translation
