//! This module provides an implementation for VMX-based virtualization.
//! It encapsulates the necessary components for VMX initialization and setup,
//! including the Vmxon, Vmcs, DescriptorTables, and other relevant data structures.

use {
    crate::{
        error::HypervisorError,
        intel::{
            descriptor::DescriptorTables,
            diag,
            paging::PageTables,
            shared_data::SharedData,
            support,
            vcpu::Vcpu,
            vmcs::Vmcs,
            vmlaunch::launch_vm,
            vmstack::{VmStack, STACK_CONTENTS_SIZE},
            vmxon::{ControlRegisterSnapshot, Vmxon},
        },
        utils::capture::GuestRegisters,
        utils::{
            alloc::{KernelAlloc, PhysicalAllocator},
            capture::CONTEXT,
            nt::{IDENTITY_CR3, NTOSKRNL_CR3},
        },
    },
    alloc::boxed::Box,
    core::ptr::NonNull,
};

/// Represents the VMX structure with essential components for VMX virtualization.
///
/// This structure contains the VMXON region, VMCS region, descriptor tables, Host RSP, Guest registers and Extened Page Tables (EPT) required for VMX operations.
///
/// # Memory Allocation Considerations
///
/// The boxed pointers for certain components within the `Vmx` structure ensure that they remain allocated throughout the VMX lifecycle.
/// - `PhysicalAllocator` utilizes `MmAllocateContiguousMemorySpecifyCacheNode` for memory operations.
/// - `KernelAlloc` utilizes `ExAllocatePool` or `ExAllocatePoolWithTag` for memory operations.
///
/// Care is taken to prevent premature deallocations, especially at high IRQLs.
#[repr(C, align(4096))]
pub struct Vmx {
    /// Virtual address of the VMXON region, aligned to a 4-KByte boundary.
    /// Allocated using `MmAllocateContiguousMemorySpecifyCacheNode`.
    pub vmxon_region: Box<Vmxon, PhysicalAllocator>,

    /// Virtual address of the VMCS region, aligned to a 4-KByte boundary.
    /// Allocated using `MmAllocateContiguousMemorySpecifyCacheNode`.
    pub vmcs_region: Box<Vmcs, PhysicalAllocator>,

    /// Virtual address of the guest's descriptor tables, including GDT and IDT.
    /// Allocated using `ExAllocatePool` or `ExAllocatePoolWithTag`.
    pub guest_descriptor_table: Box<DescriptorTables, KernelAlloc>,

    /// Virtual address of the host's descriptor tables, including GDT and IDT.
    /// Allocated using `ExAllocatePool` or `ExAllocatePoolWithTag`.
    pub host_descriptor_table: Box<DescriptorTables, KernelAlloc>,

    /// Virtual address of the host's stack, aligned to a 4-KByte boundary.
    /// Allocated using `ExAllocatePool` or `ExAllocatePoolWithTag`.
    pub vmstack: Box<VmStack, KernelAlloc>,

    /// Virtual address of the host's paging structures, aligned to a 4-KByte boundary.
    /// Allocated using `MmAllocateContiguousMemorySpecifyCacheNode`.
    pub host_paging: Box<PageTables, PhysicalAllocator>,

    /// Control registers captured before enabling VMX operation.
    pub control_registers: ControlRegisterSnapshot,

    /// The guest's general-purpose registers state.
    pub guest_registers: GuestRegisters,

    /// The shared data between processors.
    pub shared_data: NonNull<SharedData>,

    /// Guest PA to re-cloak after MTF single-step completes.
    pub mtf_recloak_pa: Option<u64>,

    /// Cumulative guest TSC offset used to hide unavoidable CPUID VM-exit cost.
    pub tsc_offset: u64,
}

impl Vmx {
    /// Creates a new instance of the `Vmx` struct.
    ///
    /// This function allocates and initializes the necessary structures for VMX virtualization.
    /// It ensures that the memory allocations required for VMX are performed safely and efficiently.
    ///
    /// Returns a `Result` with a boxed `Vmx` instance or an `HypervisorError`.
    #[rustfmt::skip]
    pub fn new(shared_data: &mut SharedData, context: &CONTEXT) -> Result<Box<Self>, HypervisorError> {
        log::debug!("Setting up VMX");
        diag::boot_stage(500)?;

        // Allocate memory for the hypervisor's needs
        let vmxon_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let vmcs_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let mut guest_descriptor_table = Box::try_new_in(DescriptorTables::new(), KernelAlloc)?;
        let mut host_descriptor_table = Box::try_new_in(DescriptorTables::new(), KernelAlloc)?;
        let vmstack = unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };
        let mut host_paging: Box<PageTables, PhysicalAllocator> = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let guest_registers = GuestRegisters::default();
        let control_registers = ControlRegisterSnapshot::capture();
        diag::boot_stage(510)?;

        // To capture the current GDT and IDT for the guest the order is important so we can setup up a new GDT and IDT for the host.
        // This is done here instead of `setup_virtualization` because it uses a vec to allocate memory for the new GDT
        DescriptorTables::initialize_for_guest(&mut guest_descriptor_table)?;
        DescriptorTables::initialize_for_host(&mut host_descriptor_table)?;
        diag::boot_stage(520)?;

        // Build hypervisor-owned paging once per CPU and keep the identity CR3 for diagnostics.
        if unsafe { NTOSKRNL_CR3 } == 0 {
            let _ = diag::boot_stage(521);
            return Err(HypervisorError::InvalidCr3BaseAddress);
        }

        host_paging.init_hypervisor_paging(unsafe { NTOSKRNL_CR3 });
        host_paging.build_identity();
        let identity_cr3 = host_paging.get_pml4_pa()?;
        unsafe {
            if IDENTITY_CR3 == 0 {
                IDENTITY_CR3 = identity_cr3;
            }
        }
        diag::boot_stage(530)?;

        log::trace!("Creating Vmx instance");

        let instance = Self {
            vmxon_region,
            vmcs_region,
            guest_descriptor_table,
            host_descriptor_table,
            vmstack,
            host_paging,
            control_registers,
            guest_registers,
            shared_data: unsafe { NonNull::new_unchecked(shared_data as *mut _) },
            mtf_recloak_pa: None,
            tsc_offset: 0,
        };

        let mut instance = Box::new(instance);

        instance.vmstack.vmx = &mut *instance as *mut _ as _;

        diag::boot_stage(540)?;
        instance.setup_virtualization(shared_data, context)?;
        diag::boot_stage(550)?;

        log::debug!("Dumping VMCS: {:#x?}", instance.vmcs_region);
        log::debug!("Dumping CONTEXT: {:#x?}", &context);

        log::debug!("VMX setup successfully!");

        Ok(instance)
    }

    pub fn teardown_vmx_operation(&self, context: &str) {
        if let Err(error) = Vcpu::invalidate_contexts() {
            log::error!(
                "Failed to invalidate contexts during {}: {:?}",
                context,
                error
            );
        }
        if let Err(error) = support::vmxoff() {
            log::error!("Failed to cleanup VMXON during {}: {:?}", context, error);
        }
        self.restore_control_registers();
    }

    /// Sets up the virtualization environment using the VMX capabilities.
    ///
    /// This function orchestrates the setup for VMX virtualization by initializing the VMXON, Vmcs,
    /// and other relevant data structures. It also configures the guest and host state
    /// in the VMCS as well as the VMCS control fields.
    ///
    /// # Arguments
    /// * `context` - The current execution context.
    ///
    /// Returns a `Result` indicating the success or failure of the setup process.
    pub fn setup_virtualization(
        &mut self,
        shared_data: &mut SharedData,
        context: &CONTEXT,
    ) -> Result<(), HypervisorError> {
        log::debug!("Setting up virtualization");
        diag::boot_stage(600)?;

        Vmxon::setup(&mut self.vmxon_region)?;
        if let Err(error) = diag::boot_stage(610) {
            if let Err(vmxoff_error) = support::vmxoff() {
                log::error!(
                    "Failed to cleanup VMXON after boot-stage stop: {:?}",
                    vmxoff_error
                );
            }
            self.restore_control_registers();
            return Err(error);
        }
        if let Err(error) = Vcpu::invalidate_contexts() {
            log::error!(
                "Initial context invalidation failed after VMXON: {:?}",
                error
            );
            if let Err(vmxoff_error) = support::vmxoff() {
                log::error!(
                    "Failed to cleanup VMXON after context invalidation failure: {:?}",
                    vmxoff_error
                );
            }
            self.restore_control_registers();
            let _ = diag::boot_stage(611);
            return Err(error);
        }

        if let Err(error) = diag::boot_stage(620) {
            if let Err(vmxoff_error) = support::vmxoff() {
                log::error!(
                    "Failed to cleanup VMXON after boot-stage stop: {:?}",
                    vmxoff_error
                );
            }
            self.restore_control_registers();
            return Err(error);
        }
        let setup_result = (|| -> Result<(), HypervisorError> {
            Vmcs::setup(&mut self.vmcs_region)?;
            VmStack::setup(&mut self.vmstack)?;

            /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4 GUEST-STATE AREA */
            Vmcs::setup_guest_registers_state(
                &context,
                &self.guest_descriptor_table,
                &mut self.guest_registers,
            )?;

            /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA */
            Vmcs::setup_host_registers_state(&context, &self.host_descriptor_table)?;

            /*
             * VMX controls:
             * Intel® 64 and IA-32 Architectures Software Developer's Manual references:
             * - 25.6 VM-EXECUTION CONTROL FIELDS
             * - 25.7 VM-EXIT CONTROL FIELDS
             * - 25.8 VM-ENTRY CONTROL FIELDS
             */
            Vmcs::setup_vmcs_control_fields(shared_data)?;

            Ok(())
        })();

        if let Err(error) = setup_result {
            log::error!("Virtualization setup failed after VMXON: {:?}", error);
            let _ = diag::boot_stage(621);
            if let Err(invalidate_error) = Vcpu::invalidate_contexts() {
                log::error!(
                    "Failed to invalidate contexts during VMXON cleanup: {:?}",
                    invalidate_error
                );
            }
            if let Err(vmxoff_error) = support::vmxoff() {
                log::error!(
                    "Failed to cleanup VMXON after setup failure: {:?}",
                    vmxoff_error
                );
            }
            self.restore_control_registers();
            return Err(error);
        }

        log::debug!("Virtualization setup successfully!");
        if let Err(error) = diag::boot_stage(630) {
            self.teardown_vmx_operation("boot-stage stop");
            return Err(error);
        }

        Ok(())
    }

    /// Executes the Virtual Machine (VM) and handles VM-exits.
    ///
    /// This method will continuously execute the VM until a VM-exit event occurs. Upon VM-exit,
    /// it updates the VM state, interprets the VM-exit reason, and handles it appropriately.
    /// The loop continues until an unhandled or error-causing VM-exit is encountered.
    pub fn run(&mut self, cpu_index: u32) -> Result<(), HypervisorError> {
        log::trace!("Executing VMLAUNCH to run the guest until a VM-exit event occurs");

        let stack_contents_ptr = self.vmstack.stack_contents.as_mut_ptr();
        let vmcs_host_rsp = unsafe { stack_contents_ptr.offset(STACK_CONTENTS_SIZE as isize) };

        log::trace!("Vmx: {:#p}", self.vmstack.vmx);

        log::info!("Launching VM for processor {}", cpu_index);
        if let Err(error) = diag::boot_stage(700 + cpu_index as u64) {
            self.teardown_vmx_operation("boot-stage stop");
            return Err(error);
        }
        unsafe { launch_vm(&mut self.guest_registers, vmcs_host_rsp as *mut u64) };

        self.restore_control_registers();
        let _ = diag::boot_stage(790 + cpu_index as u64);
        Err(HypervisorError::VMLAUNCHFailed)
    }

    pub fn restore_control_registers(&self) {
        self.control_registers.restore();
    }

    /// Returns a shared reference to the shared data.
    ///
    /// # Safety
    ///
    /// The pointer must be valid for the lifetime of the hypervisor.
    /// Multiple CPUs may hold shared references concurrently.
    pub fn shared_data_ref(&self) -> &SharedData {
        unsafe { self.shared_data.as_ref() }
    }

    /// Returns a mutable reference to the shared data.
    ///
    /// # Safety
    ///
    /// Caller must ensure no other CPU concurrently accesses the same
    /// fields being mutated (e.g., EPT page table modifications via VMCALL
    /// are serialized by the single-threaded CPL0 caller).
    pub fn shared_data_mut(&mut self) -> &mut SharedData {
        unsafe { self.shared_data.as_mut() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_surfaces_vm_entry_failure_to_caller() {
        fn assert_signature(_: fn(&mut Vmx, u32) -> Result<(), HypervisorError>) {}

        assert_signature(Vmx::run);
    }
}
