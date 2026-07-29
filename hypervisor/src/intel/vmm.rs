//! The main module for the hypervisor.

use {
    crate::{
        error::HypervisorError,
        intel::{
            diag,
            ept::{hooks::HookManager, paging::Ept},
            shared_data::SharedData,
            vcpu::Vcpu,
            vmcs::Vmcs,
            vmxon::Vmxon,
        },
        utils::{
            alloc::PhysicalAllocator,
            processor::{
                clear_virtualization_failures, current_processor_index, mark_virtualization_failure,
                is_virtualized, processor_count, virtualization_failure_count, yield_execution,
                ProcessorExecutor,
            },
        },
    },
    alloc::{boxed::Box, vec::Vec},
    core::{
        mem::ManuallyDrop,
        sync::atomic::{AtomicBool, AtomicU32, Ordering},
    },
    wdk_sys::{
        ntddk::{
            KeDelayExecutionThread, PsCreateSystemThread, PsTerminateSystemThread, ZwClose,
            ZwWaitForSingleObject,
        },
        _MODE, HANDLE, LARGE_INTEGER, NT_SUCCESS, PVOID, STATUS_SUCCESS, THREAD_ALL_ACCESS,
    },
};

const NO_SKIP_CPU: u32 = u32::MAX;
const SKIP_CPU_INDEX: u32 = parse_skip_cpu(option_env!("HV_SKIP_CPU"));
const SMP_LAUNCH_YIELD_LIMIT: u32 = 2_000_000;
const SMP_WORKER_WAIT_TIMEOUT_100NS: i64 = -5_000_000; // 500 ms

struct SmpLaunchState {
    ready: AtomicU32,
    released: AtomicU32,
    active: AtomicU32,
    go: AtomicBool,
    abort: AtomicBool,
    stop: AtomicBool,
}

struct SmpLaunchContext {
    vcpu: *mut Vcpu,
    shared_data: *const SharedData,
    state: *const SmpLaunchState,
    cpu_index: u32,
}

unsafe impl Send for SmpLaunchContext {}
unsafe impl Sync for SmpLaunchContext {}

#[derive(Default)]
pub struct HypervisorBuilder {
    /// The primary extended page table.
    primary_ept: Option<Box<Ept, PhysicalAllocator>>,

    #[cfg(feature = "secondary-ept")]
    /// The secondary extended page table.
    secondary_ept: Option<Box<Ept, PhysicalAllocator>>,

    /// The hook manager.
    hook_manager: Option<Box<HookManager>>,
}

impl HypervisorBuilder {
    /// Creates a new HypervisorBuilder instance.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if hypervisor initialization was successful, or `Err` if there was an error.
    pub fn build(self) -> Result<Hypervisor, HypervisorError> {
        log::debug!("Building hypervisor");

        Hypervisor::check_supported_cpu()?;

        let mut processors: Vec<Vcpu> = Vec::new();

        for i in 0..processor_count() {
            processors.push(Vcpu::new(i)?);
        }

        log::info!("Found {} processors", processors.len());

        let hook_manager = self
            .hook_manager
            .ok_or(HypervisorError::HookManagerNotProvided)?;

        let primary_ept = self
            .primary_ept
            .ok_or(HypervisorError::PrimaryEPTNotProvided)?;

        #[cfg(not(feature = "secondary-ept"))]
        let shared_data = SharedData::new(primary_ept, hook_manager)?;

        #[cfg(feature = "secondary-ept")]
        let shared_data = {
            let secondary_ept = self
                .secondary_ept
                .ok_or(HypervisorError::SecondaryEPTNotProvided)?;

            SharedData::new(primary_ept, secondary_ept, hook_manager)?
        };

        Ok(Hypervisor {
            processors: ManuallyDrop::new(processors),
            shared_data: ManuallyDrop::new(shared_data),
            devirtualized: true,
            smp_state: None,
            smp_worker_handles: Vec::new(),
        })
    }

    pub fn primary_ept(mut self, ept: Box<Ept, PhysicalAllocator>) -> Self {
        self.primary_ept = Some(ept);
        self
    }

    #[cfg(feature = "secondary-ept")]
    pub fn secondary_ept(mut self, ept: Box<Ept, PhysicalAllocator>) -> Self {
        self.secondary_ept = Some(ept);
        self
    }

    pub fn hook_manager(mut self, hook_manager: Box<HookManager>) -> Self {
        self.hook_manager = Some(hook_manager);
        self
    }
}

/// The main struct representing the hypervisor.
pub struct Hypervisor {
    /// The processors to virtualize.
    processors: ManuallyDrop<Vec<Vcpu>>,

    /// The shared data between processors.
    shared_data: ManuallyDrop<Box<SharedData>>,

    /// Whether all processors are known to be outside VMX non-root operation.
    devirtualized: bool,

    /// SMP launch state is kept alive until every worker has exited. A worker
    /// returns from the captured guest context while VMX is still active and
    /// therefore cannot borrow a short-lived launch barrier.
    smp_state: Option<Box<SmpLaunchState>>,

    /// Thread handles for SMP launch workers. They are joined before VCPU and
    /// shared hypervisor state is released.
    smp_worker_handles: Vec<HANDLE>,
}

/// A successful VMLAUNCH returns to the captured guest context, not to the
/// worker's root-mode call stack. Keep the worker pinned while VMX is live,
/// then terminate it only after the owner has completed VMXOFF on that CPU.
fn park_virtualized_worker(state: &SmpLaunchState, executor: ProcessorExecutor) {
    let mut interval = LARGE_INTEGER { QuadPart: -10_000 };
    loop {
        if state.stop.load(Ordering::Acquire) {
            drop(executor);
            unsafe {
                let _ = PsTerminateSystemThread(STATUS_SUCCESS);
            }
            return;
        }
        unsafe {
            let _ = KeDelayExecutionThread(_MODE::KernelMode as _, 0, &mut interval);
        }
    }
}

unsafe extern "C" fn smp_launch_thread(start_context: PVOID) {
    if start_context.is_null() {
        let _ = PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    let context = Box::from_raw(start_context as *mut SmpLaunchContext);
    let state = &*context.state;
    let Some(executor) = ProcessorExecutor::switch_to_processor(context.cpu_index) else {
        state.ready.fetch_add(1, Ordering::Release);
        state.abort.store(true, Ordering::Release);
        let _ = PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    };

    if current_processor_index() != context.cpu_index {
        state.ready.fetch_add(1, Ordering::Release);
        state.abort.store(true, Ordering::Release);
        drop(executor);
        let _ = PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    state.ready.fetch_add(1, Ordering::Release);
    while !state.go.load(Ordering::Acquire) {
        if state.abort.load(Ordering::Acquire) {
            drop(executor);
            let _ = PsTerminateSystemThread(STATUS_SUCCESS);
            return;
        }
        yield_execution();
    }

    state.released.fetch_add(1, Ordering::Release);
    if state.abort.load(Ordering::Acquire) || state.stop.load(Ordering::Acquire) {
        drop(executor);
        let _ = PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    // Do not execute VMLAUNCH from KeExpandKernelStackAndCallout. Its
    // expanded stack is temporary, while the guest return context must stay
    // valid after the launch returns to the worker.
    let result = (&mut *context.vcpu).virtualize_cpu(&*context.shared_data);
    if result.is_err() {
        // A post-launch boot-stage failure returns through the guest
        // continuation while VMX is still active. Tear it down from that
        // same guest context before terminating the worker; otherwise a dead
        // worker can leave the logical processor permanently in VMX non-root.
        if is_virtualized() {
            if let Err(error) = (&*context.vcpu).devirtualize_cpu() {
                log::error!(
                    "Failed to devirtualize worker CPU {} after launch error: {:?}",
                    context.cpu_index,
                    error
                );
            }
        }
        mark_virtualization_failure(context.cpu_index);
        drop(executor);
        let _ = PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    // `virtualize_cpu` returned from the captured guest context while VMX
    // remains active. Publish readiness and keep the affinity guard alive
    // until `devirtualize_system` has completed VMXOFF.
    state.active.fetch_add(1, Ordering::Release);
    park_virtualized_worker(state, executor);
}

fn wait_for_smp_ready(state_ptr: *const SmpLaunchState, expected: u32) -> bool {
    for _ in 0..SMP_LAUNCH_YIELD_LIMIT {
        let state = unsafe { &*state_ptr };
        if state.abort.load(Ordering::Acquire) {
            return false;
        }
        if state.ready.load(Ordering::Acquire) >= expected {
            return true;
        }
        yield_execution();
    }
    false
}

fn wait_for_smp_released(state_ptr: *const SmpLaunchState, expected: u32) -> bool {
    for _ in 0..SMP_LAUNCH_YIELD_LIMIT {
        if unsafe { (&*state_ptr).released.load(Ordering::Acquire) } >= expected {
            return true;
        }
        yield_execution();
    }
    false
}

fn wait_for_smp_active(state_ptr: *const SmpLaunchState, expected: u32) -> bool {
    for _ in 0..SMP_LAUNCH_YIELD_LIMIT {
        let state = unsafe { &*state_ptr };
        if state.abort.load(Ordering::Acquire) || virtualization_failure_count() != 0 {
            return false;
        }
        if state.active.load(Ordering::Acquire) >= expected {
            return true;
        }
        yield_execution();
    }
    false
}

impl Hypervisor {
    /// Creates a new HypervisorBuilder instance.
    pub fn builder() -> HypervisorBuilder {
        HypervisorBuilder::default()
    }

    /// Virtualizes the system's processors.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the virtualization was successful, or `Err` if there was an error.
    pub fn virtualize_core(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Virtualizing processors");

        let smp = processor_count() > 1;
        if smp && SKIP_CPU_INDEX != NO_SKIP_CPU {
            log::error!(
                "Refusing SMP virtualization with HV_SKIP_CPU={} because all CPUs must enter VMX",
                SKIP_CPU_INDEX
            );
            return Err(HypervisorError::VMXUnsupported);
        }

        // Validate VMX control capabilities on every CPU before the first
        // VMLAUNCH, avoiding partial virtualization on heterogeneous systems.
        for processor in self.processors.iter() {
            if cpu_virtualization_is_skipped(processor.id()) {
                continue;
            }
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };
            let result = Vmxon::preflight().and_then(|()| Vmcs::preflight_vmcs_control_fields());
            drop(executor);
            result?;
        }

        // VMLAUNCH captures the current guest continuation stack. Always use
        // the persistent worker path for the normal configuration, including
        // a one-CPU machine, so the captured context never points into
        // KeExpandKernelStackAndCallout's temporary expanded stack.
        if smp || SKIP_CPU_INDEX == NO_SKIP_CPU {
            return self.virtualize_processors_smp();
        }

        // A deliberately skipped single CPU is retained only for the legacy
        // test configuration. It must not be used by the normal driver path.
        for processor in self.processors.iter_mut() {
            if cpu_virtualization_is_skipped(processor.id()) {
                log::warn!("Skipping virtualization for processor {}", processor.id());
                diag::boot_stage(330 + processor.id() as u64)?;
                continue;
            }

            diag::boot_stage(300 + processor.id() as u64)?;
            log::info!("hv stage 300 cpu={}", processor.id());
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                let _ = diag::boot_stage(390 + processor.id() as u64);
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            if let Err(error) = diag::boot_stage(310 + processor.id() as u64) {
                drop(executor);
                return Err(error);
            }
            self.devirtualized = false;
            processor.virtualize_cpu(self.shared_data.as_ref())?;
            if let Err(error) = diag::boot_stage(320 + processor.id() as u64) {
                drop(executor);
                return Err(error);
            }

            drop(executor);
        }

        Ok(())
    }

    /// Launches one pinned worker per logical processor. Workers remain
    /// resident after the guest context returns so a live VMX CPU is never
    /// torn down by `PsTerminateSystemThread`.
    fn virtualize_processors_smp(&mut self) -> Result<(), HypervisorError> {
        let count = self.processors.len() as u32;
        if count != processor_count() || count == 0 {
            return Err(HypervisorError::ProcessorSwitchFailed);
        }

        self.devirtualized = false;
        clear_virtualization_failures();
        let state = Box::new(SmpLaunchState {
            ready: AtomicU32::new(0),
            released: AtomicU32::new(0),
            active: AtomicU32::new(0),
            go: AtomicBool::new(false),
            abort: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let state_ptr = state.as_ref() as *const SmpLaunchState;
        let processors_ptr = self.processors.as_mut_ptr();
        let shared_data_ptr = self.shared_data.as_ref() as *const SharedData;

        for index in 0..count {
            let context = Box::new(SmpLaunchContext {
                vcpu: unsafe { processors_ptr.add(index as usize) },
                shared_data: shared_data_ptr,
                state: state_ptr,
                cpu_index: index,
            });
            let context_ptr = Box::into_raw(context);
            let mut handle: HANDLE = core::ptr::null_mut();
            let status = unsafe {
                PsCreateSystemThread(
                    &mut handle,
                    THREAD_ALL_ACCESS,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    Some(smp_launch_thread),
                    context_ptr as PVOID,
                )
            };
            if !NT_SUCCESS(status) {
                unsafe {
                    drop(Box::from_raw(context_ptr));
                    (*state_ptr).abort.store(true, Ordering::Release);
                }
                for _ in 0..SMP_LAUNCH_YIELD_LIMIT {
                    if unsafe { (*state_ptr).ready.load(Ordering::Acquire) } >= index {
                        break;
                    }
                    yield_execution();
                }
                // Keep the barrier owned by `self`; workers may still be
                // observing `abort` and must never dereference freed state.
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            }
            self.smp_worker_handles.push(handle);
        }

        if !wait_for_smp_ready(state_ptr, count) {
            unsafe {
                (*state_ptr).abort.store(true, Ordering::Release);
            }
            self.smp_state = Some(state);
            return Err(HypervisorError::ProcessorSwitchFailed);
        }
        unsafe {
            (*state_ptr).go.store(true, Ordering::Release);
        }
        if !wait_for_smp_released(state_ptr, count) {
            unsafe {
                (*state_ptr).abort.store(true, Ordering::Release);
            }
            self.smp_state = Some(state);
            return Err(HypervisorError::ProcessorSwitchFailed);
        }
        if !wait_for_smp_active(state_ptr, count) {
            self.smp_state = Some(state);
            return Err(HypervisorError::ProcessorSwitchFailed);
        }

        // Workers continue to use the barrier while parked. Keep it owned by
        // the Hypervisor until VMXOFF has completed and all workers joined.
        self.smp_state = Some(state);
        Ok(())
    }

    fn stop_smp_workers(&mut self) -> bool {
        let Some(state) = self.smp_state.as_ref() else {
            return self.smp_worker_handles.is_empty();
        };

        state.stop.store(true, Ordering::Release);
        let mut all_stopped = true;
        for handle in &mut self.smp_worker_handles {
            if handle.is_null() {
                continue;
            }

            let mut timeout = LARGE_INTEGER {
                QuadPart: SMP_WORKER_WAIT_TIMEOUT_100NS,
            };
            let wait_status = unsafe { ZwWaitForSingleObject(*handle, false as _, &mut timeout) };
            if !NT_SUCCESS(wait_status) {
                log::error!(
                    "SMP worker did not exit within bounded wait (status {:#x})",
                    wait_status
                );
                all_stopped = false;
                continue;
            }

            let close_status = unsafe { ZwClose(*handle) };
            if !NT_SUCCESS(close_status) {
                log::error!("SMP worker handle close failed: {:#x}", close_status);
                all_stopped = false;
                continue;
            }
            *handle = core::ptr::null_mut();
        }

        if all_stopped {
            self.smp_worker_handles.clear();
            self.smp_state = None;
        }
        all_stopped
    }

    /// Reverts the virtualization of the system's processors.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the devirtualization was successful, or `Err` if there was an error.
    pub fn devirtualize_system(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Devirtualizing processors");

        if self.devirtualized {
            return if self.smp_state.is_none() && self.smp_worker_handles.is_empty() {
                Ok(())
            } else if self.stop_smp_workers() {
                Ok(())
            } else {
                Err(HypervisorError::ProcessorSwitchFailed)
            };
        }

        let mut first_error = None;
        for processor in self.processors.iter_mut() {
            diag::set_boot_stage(800 + processor.id() as u64);
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                diag::set_boot_stage(890 + processor.id() as u64);
                if first_error.is_none() {
                    first_error = Some(HypervisorError::ProcessorSwitchFailed);
                }
                continue;
            };

            if let Err(error) = processor.devirtualize_cpu() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            diag::set_boot_stage(820 + processor.id() as u64);

            drop(executor);
        }

        if let Some(error) = first_error {
            return Err(error);
        }

        if !self.stop_smp_workers() {
            return Err(HypervisorError::ProcessorSwitchFailed);
        }

        self.devirtualized = true;

        Ok(())
    }

    /// Check if the CPU is supported.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the CPU is supported, or `Err` if it's not.
    fn check_supported_cpu() -> Result<(), HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.6 DISCOVERING SUPPORT FOR VMX */
        Self::has_intel_cpu()?;
        log::info!("CPU is Intel");

        Self::has_vmx_support()?;
        log::info!("Virtual Machine Extension (VMX) technology is supported");

        Self::has_mtrr()?;
        log::info!("Memory Type Range Registers (MTRRs) are supported");

        Ok(())
    }

    /// Check to see if CPU is Intel (“GenuineIntel”).
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the CPU is Intel, or `Err` if it's not.
    fn has_intel_cpu() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(vi) = cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return Ok(());
            }
        }
        Err(HypervisorError::CPUUnsupported)
    }

    /// Check processor support for Virtual Machine Extension (VMX) technology.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if VMX technology is supported, or `Err` if it's not.
    fn has_vmx_support() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        Err(HypervisorError::VMXUnsupported)
    }

    /// Check processor support for Memory Type Range Registers (MTRRs).
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if MTRRs are supported, or `Err` if it's not.
    fn has_mtrr() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_mtrr() {
                return Ok(());
            }
        }
        Err(HypervisorError::MTRRUnsupported)
    }
}

const fn parse_skip_cpu(value: Option<&str>) -> u32 {
    let Some(value) = value else {
        return NO_SKIP_CPU;
    };

    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return NO_SKIP_CPU;
    }

    let mut i = 0;
    let mut parsed = 0u32;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte < b'0' || byte > b'9' {
            return NO_SKIP_CPU;
        }
        parsed = parsed
            .saturating_mul(10)
            .saturating_add((byte - b'0') as u32);
        i += 1;
    }
    parsed
}

fn cpu_virtualization_is_skipped(index: u32) -> bool {
    cpu_virtualization_is_skipped_with_config(SKIP_CPU_INDEX, index)
}

fn cpu_virtualization_is_skipped_with_config(skip_cpu: u32, index: u32) -> bool {
    skip_cpu != NO_SKIP_CPU && skip_cpu == index
}

fn drop_should_release_owned_resources(devirtualized: bool, cleanup_succeeded: bool) -> bool {
    devirtualized || cleanup_succeeded
}

impl Drop for Hypervisor {
    /// Handles the dropping of the `Hypervisor` instance.
    ///
    /// When a `Hypervisor` instance goes out of scope or is explicitly dropped,
    /// this method attempts to devirtualize the system and logs the result.
    fn drop(&mut self) {
        let resources_quiesced =
            self.devirtualized && self.smp_state.is_none() && self.smp_worker_handles.is_empty();
        let cleanup_succeeded = if resources_quiesced {
            true
        } else {
            match self.devirtualize_system() {
                Ok(_) => {
                    log::trace!("Devirtualized successfully!");
                    true
                }
                Err(err) => {
                    log::error!(
                        "Failed to devirtualize {}; leaking hypervisor resources",
                        err
                    );
                    false
                }
            }
        };

        if drop_should_release_owned_resources(resources_quiesced, cleanup_succeeded) {
            unsafe {
                crate::utils::nt::IDENTITY_CR3.store(0, Ordering::Release);
                ManuallyDrop::drop(&mut self.processors);
                ManuallyDrop::drop(&mut self.shared_data);
            }
        } else {
            // `Hypervisor` is about to be dropped even when cleanup failed.
            // Keep worker state and handles leaked rather than letting their
            // destructors free the barrier while a kernel thread can still
            // dereference it.
            core::mem::forget(self.smp_state.take());
            core::mem::forget(core::mem::take(&mut self.smp_worker_handles));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_releases_owned_resources_only_after_successful_cleanup() {
        assert!(drop_should_release_owned_resources(true, false));
        assert!(drop_should_release_owned_resources(false, true));
        assert!(!drop_should_release_owned_resources(false, false));
    }

    #[test]
    fn skip_cpu_parser_accepts_decimal_only() {
        assert_eq!(parse_skip_cpu(None), NO_SKIP_CPU);
        assert_eq!(parse_skip_cpu(Some("")), NO_SKIP_CPU);
        assert_eq!(parse_skip_cpu(Some("8")), 8);
        assert_eq!(parse_skip_cpu(Some("8x")), NO_SKIP_CPU);
    }

    #[test]
    fn skip_cpu_matches_only_selected_processor() {
        assert!(!cpu_virtualization_is_skipped_with_config(NO_SKIP_CPU, 8));
        assert!(cpu_virtualization_is_skipped_with_config(8, 8));
        assert!(!cpu_virtualization_is_skipped_with_config(8, 7));
    }
}
