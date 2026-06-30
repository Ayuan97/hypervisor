//! Module for handling Virtual CPU (VCPU) operations.
//! This module provides functionality to manage and control a virtualized CPU.
//! It provides mechanisms to virtualize a CPU, manage its state, and interact with its context.

extern crate alloc;

use {
    super::vmx::Vmx,
    crate::{
        error::HypervisorError,
        intel::{
            diag,
            invept::try_invept_all_contexts,
            invvpid::try_invvpid_all_contexts,
            shared_data::SharedData,
            vmexit::vmcall::{CMD_DEVIRTUALIZE, VMCALL_MAGIC},
        },
        utils::{
            capture::CONTEXT,
            processor::{clear_virtualized, is_virtualized, set_virtualized},
        },
    },
    alloc::boxed::Box,
    core::{arch::asm, cell::OnceCell, mem::MaybeUninit},
    wdk_sys::ntddk::RtlCaptureContext,
};

/// Represents a Virtual CPU (VCPU) and its associated operations.
pub struct Vcpu {
    /// The processor's unique identifier.
    index: u32,

    /// The VMX instance associated with this VCPU.
    vmx: OnceCell<Box<Vmx>>,
}

impl Vcpu {
    /// Creates and initializes a new VCPU instance for the specified processor index.
    ///
    /// # Arguments
    ///
    /// * `index` - Processor's unique identifier.
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized VCPU instance or a `HypervisorError`.
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        log::trace!("Creating processor {}", index);

        Ok(Self {
            index,
            vmx: OnceCell::new(),
        })
    }

    /// Virtualizes the current CPU.
    ///
    /// Captures the CPU's context, initializes VMX operation, adjusts control registers, and
    /// executes VMXON, VMCLEAR, VMPTRLD, and VMLAUNCH.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the virtualization process.
    pub fn virtualize_cpu(&mut self, shared_data: &mut SharedData) -> Result<(), HypervisorError> {
        log::info!("Virtualizing processor {}", self.index);
        diag::boot_stage(400 + self.index as u64)?;

        // Capture the current processor's context. The Guest will resume from this point since we capture and write this context to the guest state for each vcpu.
        log::trace!("Capturing context");
        let mut context: MaybeUninit<CONTEXT> = MaybeUninit::uninit();

        unsafe { RtlCaptureContext(context.as_mut_ptr() as _) };

        let context = unsafe { context.assume_init() };

        // Determine if we're operating as the Host (root) or Guest (non-root). Only proceed with system virtualization if operating as the Host.
        if !is_virtualized() {
            // If we are here as Guest (non-root) then that will lead to undefined behavior (UB).
            log::trace!("Preparing for virtualization");
            diag::boot_stage(410 + self.index as u64)?;

            diag::boot_stage(420 + self.index as u64)?;
            self.vmx
                .get_or_try_init(|| Vmx::new(shared_data, &context))?;

            let vmx = match self.vmx.get_mut() {
                Some(vmx) => vmx,
                None => {
                    let _ = diag::boot_stage(421 + self.index as u64);
                    return Err(HypervisorError::VmxNotInitialized);
                }
            };

            if let Err(error) = diag::boot_stage(430 + self.index as u64) {
                vmx.teardown_vmx_operation("boot-stage stop");
                return Err(error);
            }
            set_virtualized();
            log::info!("Virtualization complete for processor {}", self.index);

            let run_result = vmx.run(self.index);

            clear_virtualized();
            let _ = diag::boot_stage(440 + self.index as u64);
            return run_result;
        }

        let guest_return_stage = 750 + self.index as u64;
        if diag::stop_requested_at(guest_return_stage) {
            diag::set_boot_stage(guest_return_stage);
            let status = request_devirtualize_current_cpu();
            clear_virtualized();
            return if devirtualize_status_is_success(status) {
                Err(HypervisorError::BootStageStop)
            } else {
                log::error!(
                    "Boot-stage guest return devirtualize failed with status {:#x}",
                    status
                );
                Err(HypervisorError::VMXOFFFailed)
            };
        }

        diag::boot_stage(guest_return_stage)?;

        Ok(())
    }

    /// Devirtualizes the current CPU.
    ///
    /// Attempts to turn off VMX operation for the processor on which it's called. If the processor is
    /// already in a non-root operation (devirtualized), the function will return early without performing
    /// the devirtualization again.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the operation. Returns `Ok(())` if the processor
    /// was successfully devirtualized or was already in a devirtualized state. Returns an `Err` if the
    /// `vmxoff` operation fails.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 30.3 VMXOFF—Leave VMX Operation.
    /// - Describes the `VMXOFF` instruction which is used to devirtualize a processor.
    pub fn devirtualize_cpu(&self) -> Result<(), HypervisorError> {
        // Determine if the processor is already devirtualized.
        if !is_virtualized() {
            log::trace!("Processor {} is already devirtualized", self.index);
            return Ok(());
        }

        let status = request_devirtualize_current_cpu();
        if !devirtualize_status_is_success(status) {
            log::error!("Devirtualize VMCALL failed with status {:#x}", status);
            return Err(HypervisorError::VMXOFFFailed);
        }
        log::trace!("Processor {} has been devirtualized", self.index);

        Ok(())
    }

    /// Retrieves the processor's unique identifier.
    ///
    /// # Returns
    ///
    /// The processor's unique identifier.
    pub fn id(&self) -> u32 {
        self.index
    }

    /// Invalidates processor contexts to maintain consistency in virtualization environments.
    ///
    /// This function handles the invalidation of TLB and paging-structure caches using the INVVPID and INVEPT
    /// instructions. It ensures that any cached translations are consistent with the current state of the virtual
    /// processor and EPT configurations.
    pub fn invalidate_contexts() -> Result<(), HypervisorError> {
        log::debug!("Invalidating processor contexts");

        // Invalidate all contexts (broad operation, typically used in specific scenarios)
        //
        // Software can use the INVEPT instruction with the “all-context” INVEPT type immediately after execution of the
        // VMXON instruction or immediately prior to execution of the VMXOFF instruction. Either prevents potentially
        // undesired retention of information cached from EPT paging structures between separate uses of VMX
        // operation.
        //
        // Reference: 29.4.3.4 Guidelines for Use of the INVEPT Instruction
        try_invept_all_contexts()?;

        // Invalidate all contexts
        //
        // Software can use the INVVPID instruction with the “all-context” INVVPID type immediately after execution of
        // the VMXON instruction or immediately prior to execution of the VMXOFF instruction. Either prevents potentially
        // undesired retention of information cached from paging structures between separate uses of VMX operation.
        //
        // Reference: 29.4.3.3 Guidelines for Use of the INVVPID Instruction
        try_invvpid_all_contexts()?;

        log::debug!("Processor contexts invalidation successfully!");
        Ok(())
    }
}

fn devirtualize_status_is_success(status: u64) -> bool {
    status == 0
}

fn request_devirtualize_current_cpu() -> u64 {
    let status: u64;
    unsafe {
        asm!(
            "vmcall",
            inlateout("rax") VMCALL_MAGIC => status,
            inlateout("rcx") CMD_DEVIRTUALIZE => _,
            inlateout("rdx") 0u64 => _,
            inlateout("r8") 0u64 => _,
            inlateout("r9") 0u64 => _,
            inlateout("r10") VMCALL_MAGIC => _,
            inlateout("r11") VMCALL_MAGIC => _,
        );
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devirtualize_vmcall_status_zero_is_success() {
        assert!(devirtualize_status_is_success(0));
        assert!(!devirtualize_status_is_success(u64::MAX));
    }
}
