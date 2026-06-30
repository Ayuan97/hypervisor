//! Module for handling Virtual Machine Stack (VmStack) operations.
//! Provides mechanisms to manage and configure the virtual machine's stack, including setup, allocation, and other related operations.

use {
    crate::{
        error::HypervisorError,
        utils::{alloc::KernelAlloc, capture::M128A},
    },
    alloc::boxed::Box,
    core::mem::size_of,
    static_assertions::const_assert_eq,
};

/// The size of the kernel stack in bytes.
pub const KERNEL_STACK_SIZE: usize = 0x6000;

const VM_STACK_FOOTER_SIZE: usize =
    size_of::<*mut u64>() + size_of::<u64>() + size_of::<M128A>() * 10;

/// The size reserved for host RSP. This includes space allocated for padding.
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE - VM_STACK_FOOTER_SIZE;

/// Represents the Virtual Machine Stack (VmStack).
///
/// The structure is designed to align with 4-KByte boundaries and ensures proper setup for the host RSP during VM execution.
#[repr(C, align(4096))]
pub struct VmStack {
    /// The main contents of the VM stack during VM-exit. VMCS_HOST_RSP points to the end of this array inside the VMCS.
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],

    /// A pointer to the `Vmx` instance, needed for the `launch_vm` assembly function, which is passed to vmexit handler.
    pub vmx: *mut u64,

    /// Original host RSP captured before switching to the VM stack.
    pub original_rsp: u64,

    /// Host XMM nonvolatile registers saved before loading guest state.
    pub host_xmm6: M128A,
    pub host_xmm7: M128A,
    pub host_xmm8: M128A,
    pub host_xmm9: M128A,
    pub host_xmm10: M128A,
    pub host_xmm11: M128A,
    pub host_xmm12: M128A,
    pub host_xmm13: M128A,
    pub host_xmm14: M128A,
    pub host_xmm15: M128A,
}
const_assert_eq!(size_of::<VmStack>(), KERNEL_STACK_SIZE);
const_assert_eq!(size_of::<VmStack>() % 4096, 0);

impl VmStack {
    /// Sets up the VMCS_HOST_RSP region.
    ///
    /// Initializes the VM stack, ensuring it's properly aligned and configured for host execution.
    ///
    /// # Arguments
    ///
    /// * `vmstack` - A mutable reference to the VM stack.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the setup process.
    pub fn setup(vmstack: &mut Box<VmStack, KernelAlloc>) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMCS_HOST_RSP region");
        log::trace!("VMCS_HOST_RSP Virtual Address: {:p}", vmstack);

        // Initialize the VM stack contents and reserved space.
        vmstack.stack_contents = [0u8; STACK_CONTENTS_SIZE];

        // We don't null `vmx` because it should already be populated and we don't want to overwrite it.

        vmstack.original_rsp = 0;
        vmstack.host_xmm6 = M128A::default();
        vmstack.host_xmm7 = M128A::default();
        vmstack.host_xmm8 = M128A::default();
        vmstack.host_xmm9 = M128A::default();
        vmstack.host_xmm10 = M128A::default();
        vmstack.host_xmm11 = M128A::default();
        vmstack.host_xmm12 = M128A::default();
        vmstack.host_xmm13 = M128A::default();
        vmstack.host_xmm14 = M128A::default();
        vmstack.host_xmm15 = M128A::default();

        log::debug!("VMCS_HOST_RSP setup successfully!");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    #[test]
    fn footer_offsets_match_launch_vm_assembly_contract() {
        let vmx_offset = offset_of!(VmStack, vmx);

        assert_eq!(vmx_offset, STACK_CONTENTS_SIZE);
        assert_eq!(offset_of!(VmStack, original_rsp) - vmx_offset, 0x08);
        assert_eq!(offset_of!(VmStack, host_xmm6) - vmx_offset, 0x10);
        assert_eq!(offset_of!(VmStack, host_xmm7) - vmx_offset, 0x20);
        assert_eq!(offset_of!(VmStack, host_xmm8) - vmx_offset, 0x30);
        assert_eq!(offset_of!(VmStack, host_xmm9) - vmx_offset, 0x40);
        assert_eq!(offset_of!(VmStack, host_xmm10) - vmx_offset, 0x50);
        assert_eq!(offset_of!(VmStack, host_xmm11) - vmx_offset, 0x60);
        assert_eq!(offset_of!(VmStack, host_xmm12) - vmx_offset, 0x70);
        assert_eq!(offset_of!(VmStack, host_xmm13) - vmx_offset, 0x80);
        assert_eq!(offset_of!(VmStack, host_xmm14) - vmx_offset, 0x90);
        assert_eq!(offset_of!(VmStack, host_xmm15) - vmx_offset, 0xa0);
    }

    #[test]
    fn host_rsp_layout_matches_vmexit_stub_contract() {
        const LAUNCH_STACK_SAVE_SIZE: usize = 0x80;
        let host_rsp_offset = STACK_CONTENTS_SIZE - LAUNCH_STACK_SAVE_SIZE;

        assert_eq!(host_rsp_offset % 16, 0);
        assert_eq!(offset_of!(VmStack, vmx) - host_rsp_offset, 0x80);
        assert_eq!(offset_of!(VmStack, original_rsp) - host_rsp_offset, 0x88);
        assert_eq!(offset_of!(VmStack, host_xmm15) - host_rsp_offset, 0x120);
    }
}
