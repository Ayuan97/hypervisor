//! Module for handling Virtual CPU (VCPU) operations.
//! This module provides functionality to manage and control a virtualized CPU.
//! It provides mechanisms to virtualize a CPU, manage its state, and interact with its context.

extern crate alloc;

use {
    super::vmx::{Vmx, VmxContigPrealloc},
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
            alloc::KernelAlloc,
            capture::CONTEXT,
            processor::{clear_virtualized, is_virtualized, set_virtualized},
        },
    },
    alloc::boxed::Box,
    core::{arch::asm, cell::OnceCell, mem::MaybeUninit},
    wdk_sys::{
        ntddk::{KeGetCurrentIrql, RtlCaptureContext},
        PASSIVE_LEVEL,
    },
};

const RFLAGS_INTERRUPT_ENABLE: u32 = 1 << 9;

/// RtlCaptureContext does not promise to populate every CONTEXT member (in
/// particular the debug-register fields). Zero the record first so the later
/// VMCS setup never reads uninitialized bytes as guest state.
fn capture_context() -> CONTEXT {
    let mut context = MaybeUninit::<CONTEXT>::zeroed();
    unsafe { RtlCaptureContext(context.as_mut_ptr() as _) };
    unsafe { context.assume_init() }
}

/// Represents a Virtual CPU (VCPU) and its associated operations.
pub struct Vcpu {
    /// The processor's unique identifier.
    index: u32,

    /// The VMX instance associated with this VCPU.
    vmx: OnceCell<Box<Vmx, KernelAlloc>>,

    /// Complete launch storage installed by the owner before any CPU enters
    /// VMX. Unused storage stays here until every worker is native.
    launch_prealloc: Option<VmxContigPrealloc>,
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
            launch_prealloc: None,
        })
    }

    pub(crate) fn install_launch_prealloc(
        &mut self,
        prealloc: VmxContigPrealloc,
    ) -> Result<(), HypervisorError> {
        if self.launch_prealloc.is_some() || self.vmx.get().is_some() {
            return Err(HypervisorError::ProcessorSwitchFailed);
        }
        self.launch_prealloc = Some(prealloc);
        Ok(())
    }

    /// Virtualizes the current CPU (capture → Vmx::new → VMLAUNCH).
    pub fn virtualize_cpu(&mut self, shared_data: &SharedData) -> Result<(), HypervisorError> {
        if self.launch_prealloc.is_some() || self.vmx.get().is_some() {
            return Err(HypervisorError::ProcessorSwitchFailed);
        }
        self.install_launch_prealloc(VmxContigPrealloc::allocate()?)?;
        self.virtualize_cpu_prealloc(shared_data)
    }

    /// Same as `virtualize_cpu`, using complete storage installed by the BSP.
    ///
    /// A late context refreshes guest architectural state immediately before
    /// VMLAUNCH. The exact continuation RIP/RSP/RFLAGS are installed by
    /// `launch_vm` from its call-site state.
    pub fn virtualize_cpu_prealloc(
        &mut self,
        shared_data: &SharedData,
    ) -> Result<(), HypervisorError> {
        if self.vmx.get().is_some() {
            return Err(HypervisorError::VmxNotInitialized);
        }
        let prealloc = self
            .launch_prealloc
            .take()
            .ok_or(HypervisorError::VmxNotInitialized)?;
        let instance = Vmx::from_prealloc(shared_data, prealloc);
        if let Err(instance) = self.vmx.set(instance) {
            // Unreachable with exclusive Vcpu ownership. If violated, retain
            // the allocation because hardware may already reference it.
            core::mem::forget(instance);
            return Err(HypervisorError::VmxNotInitialized);
        }

        log::info!("Virtualizing processor {}", self.index);
        diag::boot_stage(400 + self.index as u64)?;

        // Early capture: only feeds Vmx::new host/guest descriptor setup.
        // Guest does NOT resume here.
        log::trace!("Capturing setup context");
        let context = capture_context();
        let setup_irql = unsafe { KeGetCurrentIrql() };
        if !launch_context_values_are_safe(setup_irql, context.EFlags) {
            log::error!(
                "Refusing VMXON on CPU {} with IRQL={} EFLAGS={:#x}",
                self.index,
                setup_irql,
                context.EFlags
            );
            return Err(HypervisorError::UnsafeLaunchContext);
        }

        log::trace!("Preparing for virtualization");
        diag::boot_stage(410 + self.index as u64)?;
        diag::boot_stage(420 + self.index as u64)?;
        let vmx = match self.vmx.get_mut() {
            Some(vmx) => vmx,
            None => {
                let _ = diag::boot_stage(421 + self.index as u64);
                return Err(HypervisorError::VmxNotInitialized);
            }
        };

        vmx.initialize(shared_data, &context)?;

        if let Err(error) = diag::boot_stage(430 + self.index as u64) {
            if let Err(teardown_error) = vmx.teardown_vmx_operation("boot-stage stop") {
                log::error!(
                    "VMX teardown failed after boot-stage stop: {:?}",
                    teardown_error
                );
                return Err(teardown_error);
            }
            return Err(error);
        }

        // Late capture: guest state must match the stack at VMLAUNCH.
        diag::set_boot_stage(690 + self.index as u64);
        log::trace!("Capturing launch context");
        let late = capture_context();

        let launch_irql = unsafe { KeGetCurrentIrql() };
        if !launch_context_values_are_safe(launch_irql, late.EFlags) {
            log::error!(
                "Refusing VMLAUNCH on CPU {} with IRQL={} EFLAGS={:#x}",
                self.index,
                launch_irql,
                late.EFlags
            );
            return match vmx.teardown_vmx_operation("unsafe launch context") {
                Ok(()) => Err(HypervisorError::UnsafeLaunchContext),
                Err(error) => Err(error),
            };
        }

        if let Err(error) = vmx.reapply_guest_context(&late) {
            log::error!(
                "Failed to reapply late guest context on CPU {}: {:?}",
                self.index,
                error
            );
            if let Err(teardown_error) = vmx.teardown_vmx_operation("late guest context") {
                log::error!(
                    "VMX teardown failed after late context error: {:?}",
                    teardown_error
                );
                return Err(teardown_error);
            }
            return Err(error);
        }

        set_virtualized();
        // 695 = late context applied; Vmx::run sets 700 at the VMLAUNCH insn.
        diag::set_boot_stage(695 + self.index as u64);
        log::info!("VMLAUNCH on processor {}", self.index);
        match vmx.run(self.index) {
            Ok(()) if is_virtualized() => self.guest_return_from_launch(),
            Ok(()) => {
                log::error!(
                    "CPU {} returned through the guest continuation after VMX was cleared",
                    self.index
                );
                Err(HypervisorError::VMLAUNCHFailed)
            }
            Err(error) => {
                // A failed VMXOFF means the CPU may still reference this
                // VCPU's VMCS/stack. Keep the software gate set so outer
                // cleanup retains the backing allocation and driver image.
                if !matches!(&error, HypervisorError::VMXOFFFailed) {
                    clear_virtualized();
                }
                let _ = diag::boot_stage(440 + self.index as u64);
                Err(error)
            }
        }
    }

    fn guest_return_from_launch(&self) -> Result<(), HypervisorError> {
        // Monotonic per-CPU guest-return: 700 + 3*cpu + 1 (see launch_stage_band).
        let guest_return_stage =
            diag::launch_stage_band(self.index, diag::LAUNCH_PHASE_GUEST_RETURN);
        if diag::stop_requested_at(guest_return_stage) {
            diag::set_boot_stage(guest_return_stage);
            let status = request_devirtualize_current_cpu();
            return if devirtualize_status_is_success(status) {
                clear_virtualized();
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

const fn launch_context_values_are_safe(irql: u8, eflags: u32) -> bool {
    irql as u32 == PASSIVE_LEVEL && eflags & RFLAGS_INTERRUPT_ENABLE != 0
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

    #[test]
    fn launch_requires_passive_irql_with_interrupts_enabled() {
        assert!(launch_context_values_are_safe(0, 0x202));
        assert!(!launch_context_values_are_safe(1, 0x202));
        assert!(!launch_context_values_are_safe(2, 0x202));
        assert!(!launch_context_values_are_safe(0, 0x002));
    }
}
