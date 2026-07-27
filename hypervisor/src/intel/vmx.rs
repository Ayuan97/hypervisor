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
            addresses::PhysicalAddress,
            alloc::{KernelAlloc, PhysicalAllocator},
            capture::CONTEXT,
            nt::{IDENTITY_CR3, NTOSKRNL_CR3},
        },
    },
    alloc::boxed::Box,
    core::{cell::UnsafeCell, ptr::NonNull},
    x86::{cpuid::cpuid, msr, vmx::vmcs},
};

const IA32_TSC_AUX: u32 = 0xC000_0103;
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
const MAX_TRANSITION_MSRS: usize = 2;

/// One entry in a VM-entry/VM-exit MSR load/store area (Intel SDM 25.7/25.8).
#[repr(C, align(16))]
struct VmxMsrEntry {
    index: u32,
    reserved: u32,
    value: UnsafeCell<u64>,
}

impl VmxMsrEntry {
    const fn new(index: u32, value: u64) -> Self {
        Self {
            index,
            reserved: 0,
            value: UnsafeCell::new(value),
        }
    }

    fn value(&self) -> u64 {
        unsafe { core::ptr::read_volatile(self.value.get()) }
    }
}

/// Per-vCPU architectural MSRs swapped by hardware at every VM transition.
///
/// IA32_TSC_AUX must be swapped instead of software-shadowed: with RDTSC
/// exiting disabled, RDTSCP executes natively in the guest and therefore must
/// see a real guest IA32_TSC_AUX value. IA32_PERF_GLOBAL_CTRL is also swapped
/// when architectural PMU support is present so guest counters stop while the
/// VM-exit handler runs.
#[repr(C, align(16))]
struct VmxMsrList {
    entries: [VmxMsrEntry; MAX_TRANSITION_MSRS],
}

impl VmxMsrList {
    fn guest(tsc_aux: u64, perf_global_ctrl: Option<u64>) -> Self {
        Self {
            entries: [
                VmxMsrEntry::new(IA32_TSC_AUX, tsc_aux),
                VmxMsrEntry::new(
                    perf_global_ctrl.map_or(0, |_| IA32_PERF_GLOBAL_CTRL),
                    perf_global_ctrl.unwrap_or(0),
                ),
            ],
        }
    }

    fn host(tsc_aux: u64, perf_global_ctrl_present: bool) -> Self {
        Self {
            entries: [
                VmxMsrEntry::new(IA32_TSC_AUX, tsc_aux),
                // Root mode does not own the guest PMU. Loading zero stops
                // programmable/fixed counters until the matching VM-entry.
                VmxMsrEntry::new(
                    if perf_global_ctrl_present {
                        IA32_PERF_GLOBAL_CTRL
                    } else {
                        0
                    },
                    0,
                ),
            ],
        }
    }
}

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

    /// Guest values stored on VM-exit and loaded on VM-entry.
    guest_msr_state: Box<VmxMsrList, PhysicalAllocator>,

    /// Root values loaded by hardware before the VM-exit handler runs.
    host_msr_state: Box<VmxMsrList, PhysicalAllocator>,

    /// Active entries in each transition list.
    transition_msr_count: u32,

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

    /// True when the previous EPT violation on this CPU was a spurious hit
    /// on the KeBugCheckEx cloak page (see `bugcheck_hook`), MTF is armed,
    /// and the following MTF exit must re-cloak the page (X→0).
    pub bugcheck_hook_mtf_recloak: bool,

    /// Cumulative guest TSC offset used to hide unavoidable CPUID VM-exit cost.
    pub tsc_offset: u64,

    /// TSC value captured at CPUID VM-exit entry; when non-zero the next
    /// RDTSC/RDTSCP exit returns a spoofed value and clears this field.
    pub cpuid_entry_tsc: u64,
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
        let initial_tsc_aux = unsafe { msr::rdmsr(IA32_TSC_AUX) };
        let pmu_present = (cpuid!(0xA).eax & 0xff) != 0;
        let initial_perf_global_ctrl =
            pmu_present.then(|| unsafe { msr::rdmsr(IA32_PERF_GLOBAL_CTRL) });
        let guest_msr_state = Box::try_new_in(
            VmxMsrList::guest(initial_tsc_aux, initial_perf_global_ctrl),
            PhysicalAllocator,
        )?;
        let host_msr_state = Box::try_new_in(
            VmxMsrList::host(initial_tsc_aux, pmu_present),
            PhysicalAllocator,
        )?;
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
            guest_msr_state,
            host_msr_state,
            transition_msr_count: if pmu_present { 2 } else { 1 },
            guest_descriptor_table,
            host_descriptor_table,
            vmstack,
            host_paging,
            control_registers,
            guest_registers,
            shared_data: unsafe { NonNull::new_unchecked(shared_data as *mut _) },
            mtf_recloak_pa: None,
            bugcheck_hook_mtf_recloak: false,
            tsc_offset: 0,
            cpuid_entry_tsc: 0,
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

    pub fn teardown_vmx_operation(&self, context: &str) -> Result<(), HypervisorError> {
        let mut first_error = None;
        if let Err(error) = Vcpu::invalidate_contexts() {
            log::error!(
                "Failed to invalidate contexts during {}: {:?}",
                context,
                error
            );
            first_error = Some(error);
        }
        if let Err(error) = support::vmxoff() {
            log::error!("Failed to cleanup VMXON during {}: {:?}", context, error);
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        self.restore_control_registers();

        first_error.map_or(Ok(()), Err)
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
            return Err(self.cleanup_vmxon_failure("boot-stage stop", error, false));
        }
        if let Err(error) = Vcpu::invalidate_contexts() {
            log::error!(
                "Initial context invalidation failed after VMXON: {:?}",
                error
            );
            let error = self.cleanup_vmxon_failure("context invalidation failure", error, false);
            let _ = diag::boot_stage(611);
            return Err(error);
        }

        if let Err(error) = diag::boot_stage(620) {
            return Err(self.cleanup_vmxon_failure("boot-stage stop", error, true));
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
            self.setup_transition_msr_lists()?;

            Ok(())
        })();

        if let Err(error) = setup_result {
            log::error!("Virtualization setup failed after VMXON: {:?}", error);
            let _ = diag::boot_stage(621);
            return Err(self.cleanup_vmxon_failure("setup failure", error, true));
        }

        log::debug!("Virtualization setup successfully!");
        if let Err(error) = diag::boot_stage(630) {
            if let Err(teardown_error) = self.teardown_vmx_operation("boot-stage stop") {
                log::error!(
                    "VMX teardown failed after boot-stage stop: {:?}",
                    teardown_error
                );
                return Err(teardown_error);
            }
            return Err(error);
        }

        Ok(())
    }

    fn cleanup_vmxon_failure(
        &self,
        context: &str,
        original_error: HypervisorError,
        invalidate_contexts: bool,
    ) -> HypervisorError {
        let mut cleanup_error = None;
        if invalidate_contexts {
            if let Err(error) = Vcpu::invalidate_contexts() {
                log::error!(
                    "Failed to invalidate contexts during VMXON {}: {:?}",
                    context,
                    error
                );
                cleanup_error = Some(error);
            }
        }
        if let Err(error) = support::vmxoff() {
            log::error!("Failed to cleanup VMXON after {}: {:?}", context, error);
            if cleanup_error.is_none() {
                cleanup_error = Some(error);
            }
        }
        self.restore_control_registers();
        cleanup_error.unwrap_or(original_error)
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
        crate::intel::diag_trace::trace("vmlaunch: entering guest");
        if let Err(error) = diag::boot_stage(700 + cpu_index as u64) {
            if let Err(teardown_error) = self.teardown_vmx_operation("boot-stage stop") {
                log::error!(
                    "VMX teardown failed after boot-stage stop: {:?}",
                    teardown_error
                );
                return Err(teardown_error);
            }
            return Err(error);
        }
        unsafe { launch_vm(&mut self.guest_registers, vmcs_host_rsp as *mut u64) };
        crate::intel::diag_trace::trace("vmlaunch: returned (FAILED)");

        // `vmlaunch_failed` executes VMXOFF before returning to this frame.
        // Restore the guest-owned transition MSRs on that path as well; the
        // normal devirtualization path performs the same operation in
        // `leave_vmx_root`, so this is idempotent when it returns normally.
        unsafe { self.restore_guest_transition_msrs() };
        self.restore_control_registers();
        let _ = diag::boot_stage(790 + cpu_index as u64);
        Err(HypervisorError::VMLAUNCHFailed)
    }

    pub fn restore_control_registers(&self) {
        self.control_registers.restore();
    }

    fn setup_transition_msr_lists(&self) -> Result<(), HypervisorError> {
        let guest_pa = PhysicalAddress::pa_from_va(
            self.guest_msr_state.as_ref() as *const VmxMsrList as u64,
        );
        let host_pa = PhysicalAddress::pa_from_va(
            self.host_msr_state.as_ref() as *const VmxMsrList as u64,
        );

        // Intel SDM requires all VM-entry/VM-exit MSR list addresses to be
        // non-zero and 16-byte aligned.  Reject a bad translation here,
        // before VMLAUNCH turns it into a late VM-entry failure.
        if guest_pa == 0
            || host_pa == 0
            || (guest_pa & 0xF) != 0
            || (host_pa & 0xF) != 0
            || self.transition_msr_count == 0
            || self.transition_msr_count as usize > MAX_TRANSITION_MSRS
        {
            log::error!(
                "Invalid VM transition MSR lists: guest_pa={:#x} host_pa={:#x} count={}",
                guest_pa,
                host_pa,
                self.transition_msr_count
            );
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        support::vmwrite_checked(vmcs::control::VMEXIT_MSR_STORE_ADDR_FULL, guest_pa)?;
        support::vmwrite_checked(
            vmcs::control::VMEXIT_MSR_STORE_COUNT,
            self.transition_msr_count as u64,
        )?;
        support::vmwrite_checked(vmcs::control::VMEXIT_MSR_LOAD_ADDR_FULL, host_pa)?;
        support::vmwrite_checked(
            vmcs::control::VMEXIT_MSR_LOAD_COUNT,
            self.transition_msr_count as u64,
        )?;
        support::vmwrite_checked(vmcs::control::VMENTRY_MSR_LOAD_ADDR_FULL, guest_pa)?;
        support::vmwrite_checked(
            vmcs::control::VMENTRY_MSR_LOAD_COUNT,
            self.transition_msr_count as u64,
        )?;
        Ok(())
    }

    /// Guest IA32_TSC_AUX saved by the most recent VM-exit.
    pub fn guest_tsc_aux(&self) -> u32 {
        self.guest_msr_state.entries[0].value() as u32
    }

    /// Restore architectural guest MSRs when devirtualization returns without
    /// a matching VM-entry.
    pub unsafe fn restore_guest_transition_msrs(&self) {
        for entry in &self.guest_msr_state.entries[..self.transition_msr_count as usize] {
            msr::wrmsr(entry.index, entry.value());
        }
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

    #[test]
    fn transition_msr_lists_keep_tsc_aux_guest_owned_and_stop_root_pmu() {
        let guest = VmxMsrList::guest(0x1234, Some(0x55));
        let host = VmxMsrList::host(0x77, true);

        assert_eq!(core::mem::size_of::<VmxMsrEntry>(), 16);
        assert_eq!(guest.entries[0].index, IA32_TSC_AUX);
        assert_eq!(guest.entries[0].value(), 0x1234);
        assert_eq!(host.entries[0].value(), 0x77);
        assert_eq!(guest.entries[1].index, IA32_PERF_GLOBAL_CTRL);
        assert_eq!(guest.entries[1].value(), 0x55);
        assert_eq!(host.entries[1].index, IA32_PERF_GLOBAL_CTRL);
        assert_eq!(host.entries[1].value(), 0);
    }
}
