//! The main module for the hypervisor.

use {
    crate::{
        error::HypervisorError,
        intel::{
            diag,
            ept::{hooks::HookManager, paging::Ept},
            paging::PageTables,
            shared_data::SharedData,
            vcpu::Vcpu,
            vmcs::Vmcs,
            vmxon::Vmxon,
        },
        utils::{
            alloc::{KernelAlloc, PhysicalAllocator},
            nt::{IDENTITY_CR3, NTOSKRNL_CR3},
            processor::{
                clear_virtualization_failures, current_processor_index, is_virtualized,
                mark_virtualization_failure, processor_count, virtualization_failure_count,
                virtualized_processor_count, ProcessorExecutor,
            },
        },
    },
    alloc::{boxed::Box, vec::Vec},
    core::{
        mem::ManuallyDrop,
        sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering},
    },
    wdk_sys::{
        ntddk::{
            KeDelayExecutionThread, PsCreateSystemThread, PsTerminateSystemThread, ZwClose,
            ZwWaitForSingleObject,
        },
        _EVENT_TYPE::{NotificationEvent, SynchronizationEvent},
        _MODE, EVENT_TYPE, HANDLE, LARGE_INTEGER, NT_SUCCESS, PVOID, STATUS_SUCCESS,
        THREAD_ALL_ACCESS,
    },
};

#[cfg(not(test))]
use wdk_sys::{
    ntddk::{KeInitializeEvent, KeSetEvent, KeWaitForSingleObject},
    _KWAIT_REASON::Executive,
    KEVENT,
};

const NO_SKIP_CPU: u32 = u32::MAX;
const SKIP_CPU_INDEX: u32 = parse_skip_cpu(option_env!("HV_SKIP_CPU"));
// Bound a missing launch transition to about 10 seconds per CPU.
const SMP_LAUNCH_YIELD_LIMIT: u32 = 10_000;
const SMP_WORKER_WAIT_TIMEOUT_100NS: i64 = -5_000_000; // 500 ms
// Only the owner thread uses this delay while waiting for bounded state
// transitions. Launch workers block on dispatcher events instead of polling.
const SMP_WAIT_DELAY_100NS: i64 = -10_000;
// After each CPU finishes VMLAUNCH, let clocks/IPIs settle before the next
// LP enters VMLAUNCH under a partially virtualized machine.
// 50 ms: 2-LP 0x101 peak=770. 500 ms: 2-LP OK (re-verified path).
// 1500 ms tried after allcpu peak=770; 2-LP then showed peak=700 (CPU0 VMLAUNCH)
// on SMP path — keep 500 ms until 2-LP is re-green, then re-bisect all-LP.
const SMP_INTER_CPU_SETTLE_100NS: i64 = -5_000_000;

// CMOS keeps only the monotonic peak. Encode pinned-worker preparation below
// the 700+ VMX launch band so a large CPU index can never look like an early
// VMLAUNCH. CPUs above the 24 diagnostic slots share the final slot; the CMOS
// CPU byte is refreshed when they reach the same peak.
const PRELAUNCH_STAGE_BASE: u64 = 624;
const PRELAUNCH_STAGE_LAST_CPU_SLOT: u32 = 23;
const PRELAUNCH_PHASE_BIND: u64 = 0;
const PRELAUNCH_PHASE_PREFLIGHT: u64 = 1;
const PRELAUNCH_PHASE_READY: u64 = 2;
const PRELAUNCH_BARRIER_COMPLETE_STAGE: u64 = 696;

fn prelaunch_stage_band(cpu: u32, phase: u64) -> u64 {
    PRELAUNCH_STAGE_BASE
        + u64::from(cpu.min(PRELAUNCH_STAGE_LAST_CPU_SLOT)) * 3
        + (phase % 3)
}

const LAUNCH_GATE_OPEN: u8 = 0;
const LAUNCH_GATE_CLAIMED: u8 = 1;
const LAUNCH_GATE_ACTIVE: u8 = 2;
const LAUNCH_GATE_TERMINATED: u8 = 3;
const LAUNCH_GATE_CANCELLED: u8 = 4;
const LAUNCH_GATE_UNSAFE: u8 = 5;

fn smp_worker_wait_completed(status: i32) -> bool {
    status == STATUS_SUCCESS
}

const fn launch_barrier_is_safe(ready: u32, expected: u32, virtualized: u32) -> bool {
    ready == expected && expected != 0 && virtualized == 0
}

#[cfg(not(test))]
struct KernelEvent {
    // KeInitializeEvent links the dispatcher wait list to this address, so the
    // initialized KEVENT must remain in its final allocation.
    event: Box<KEVENT>,
}

#[cfg(not(test))]
impl KernelEvent {
    fn new(event_type: EVENT_TYPE) -> Self {
        let mut event = Box::new(KEVENT::default());
        unsafe {
            KeInitializeEvent(event.as_mut(), event_type, false as _);
        }
        Self { event }
    }

    fn signal(&self) {
        unsafe {
            let _ = KeSetEvent(self.event.as_ref() as *const KEVENT as _, 0, false as _);
        }
    }

    fn wait(&self) -> bool {
        unsafe {
            KeWaitForSingleObject(
                self.event.as_ref() as *const KEVENT as PVOID,
                Executive,
                _MODE::KernelMode as _,
                false as _,
                core::ptr::null_mut(),
            ) == STATUS_SUCCESS
        }
    }
}

#[cfg(test)]
struct KernelEvent {
    signaled: AtomicBool,
}

#[cfg(test)]
impl KernelEvent {
    fn new(_event_type: EVENT_TYPE) -> Self {
        Self {
            signaled: AtomicBool::new(false),
        }
    }

    fn signal(&self) {
        self.signaled.store(true, Ordering::Release);
    }

    fn wait(&self) -> bool {
        self.signaled.swap(false, Ordering::AcqRel)
    }
}

struct SmpLaunchState {
    /// Worker hit an intentional HV_BOOT_STOP_STAGE (not a hard failure).
    stage_stop: AtomicBool,
    ready: AtomicU32,
    launch_turn: AtomicU32,
    active: AtomicU32,
    abort: AtomicBool,
    stop: AtomicBool,
    teardown_failed: AtomicBool,
    /// Serializes timeout cancellation against the current VMX transition.
    launch_gate: AtomicU8,
    /// One auto-reset gate per pinned launch worker.
    launch_events: Vec<KernelEvent>,
    /// Manual-reset gate used to release parked workers after VMXOFF.
    stop_event: KernelEvent,
}

impl SmpLaunchState {
    fn new(processor_count: u32) -> Self {
        let mut launch_events = Vec::with_capacity(processor_count as usize);
        for _ in 0..processor_count {
            launch_events.push(KernelEvent::new(SynchronizationEvent));
        }

        Self {
            stage_stop: AtomicBool::new(false),
            ready: AtomicU32::new(0),
            launch_turn: AtomicU32::new(0),
            active: AtomicU32::new(0),
            abort: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            teardown_failed: AtomicBool::new(false),
            launch_gate: AtomicU8::new(LAUNCH_GATE_OPEN),
            launch_events,
            stop_event: KernelEvent::new(NotificationEvent),
        }
    }

    fn has_launch_turn(&self, cpu_index: u32) -> bool {
        self.launch_turn.load(Ordering::Acquire) == cpu_index
    }

    fn advance_launch_turn(&self, cpu_index: u32) -> bool {
        self.launch_turn
            .compare_exchange(
                cpu_index,
                cpu_index + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn aborted(&self) -> bool {
        self.abort.load(Ordering::Acquire)
            || self.stop.load(Ordering::Acquire)
            || virtualization_failure_count() != 0
    }

    fn prepare_launch(&self, first: bool) -> bool {
        let expected = if first {
            LAUNCH_GATE_OPEN
        } else {
            LAUNCH_GATE_ACTIVE
        };
        self.launch_gate
            .compare_exchange(
                expected,
                LAUNCH_GATE_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn claim_launch(&self) -> bool {
        self.launch_gate
            .compare_exchange(
                LAUNCH_GATE_OPEN,
                LAUNCH_GATE_CLAIMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn mark_launch_active(&self) -> bool {
        self.launch_gate
            .compare_exchange(
                LAUNCH_GATE_CLAIMED,
                LAUNCH_GATE_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn cancel_launch(&self) -> u8 {
        self.abort.store(true, Ordering::Release);
        let phase = match self.launch_gate.compare_exchange(
            LAUNCH_GATE_OPEN,
            LAUNCH_GATE_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => LAUNCH_GATE_CANCELLED,
            Err(phase) => phase,
        };
        self.signal_all_launch_workers();
        phase
    }

    fn cleanup_is_blocked(&self) -> bool {
        matches!(
            self.launch_gate.load(Ordering::Acquire),
            LAUNCH_GATE_CLAIMED | LAUNCH_GATE_UNSAFE
        )
    }

    fn signal_launch_worker(&self, cpu_index: u32) -> bool {
        let Some(event) = self.launch_events.get(cpu_index as usize) else {
            return false;
        };
        event.signal();
        true
    }

    fn signal_all_launch_workers(&self) {
        for event in &self.launch_events {
            event.signal();
        }
    }

    fn wait_for_launch(&self, cpu_index: u32) -> bool {
        self.launch_events
            .get(cpu_index as usize)
            .is_some_and(KernelEvent::wait)
    }

    fn signal_stop(&self) {
        self.stop_event.signal();
    }

    fn wait_for_stop(&self) -> bool {
        self.stop_event.wait()
    }
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

        let system_cr3 = unsafe { NTOSKRNL_CR3 };
        if system_cr3 == 0 {
            return Err(HypervisorError::InvalidCr3BaseAddress);
        }
        // All CPUs use the same immutable identity map. The previous design
        // allocated a 0x202000-byte physically contiguous copy per VCPU even
        // though only the first CR3 was published, causing 24 concurrent
        // large allocations during SMP launch.
        let mut identity_paging: Box<PageTables, KernelAlloc> =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };
        identity_paging.init_hypervisor_paging(system_cr3);
        identity_paging.build_identity();
        let identity_cr3 = identity_paging.get_pml4_pa()?;

        let mut processors: Vec<Vcpu> = Vec::new();
        // A persistent mix of virtualized and native LPs makes CPUID/EPT/VMCALL
        // behavior depend on scheduling. Refuse that configuration.
        let n = effective_processor_count()?;
        for i in 0..n {
            processors.push(Vcpu::new(i)?);
        }

        log::info!(
            "Using {} of {} logical processors (HV_MAX_CPUS)",
            processors.len(),
            processor_count()
        );

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

        IDENTITY_CR3.store(identity_cr3, Ordering::Release);
        Ok(Hypervisor {
            processors: ManuallyDrop::new(processors),
            shared_data: ManuallyDrop::new(shared_data),
            identity_paging: ManuallyDrop::new(identity_paging),
            devirtualized: true,
            launch_attempted: false,
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

    /// Single immutable identity map backing `IDENTITY_CR3` for every CPU.
    identity_paging: ManuallyDrop<Box<PageTables, KernelAlloc>>,

    /// Whether all processors are known to be outside VMX non-root operation.
    devirtualized: bool,

    /// VCPU VMX storage is intentionally one-shot. Once launch begins, a new
    /// Hypervisor must be built before VMX can be entered again.
    launch_attempted: bool,

    /// SMP launch state is kept alive until every worker has exited. A worker
    /// returns from the captured guest context while VMX is still active and
    /// therefore cannot borrow a short-lived launch barrier.
    smp_state: Option<Box<SmpLaunchState>>,

    /// Thread handles for SMP launch workers. They are joined before VCPU and
    /// shared hypervisor state is released.
    smp_worker_handles: Vec<HANDLE>,
}

fn smp_wait_delay() {
    let mut interval = LARGE_INTEGER {
        QuadPart: SMP_WAIT_DELAY_100NS,
    };
    unsafe {
        let _ = KeDelayExecutionThread(_MODE::KernelMode as _, 0, &mut interval);
    }
}

const fn launch_lifecycle_allows_start(
    launch_attempted: bool,
    devirtualized: bool,
    has_state: bool,
    has_workers: bool,
) -> bool {
    !launch_attempted && devirtualized && !has_state && !has_workers
}

fn mark_launch_terminal(state: &SmpLaunchState, safe: bool) {
    state.launch_gate.store(
        if safe {
            LAUNCH_GATE_TERMINATED
        } else {
            LAUNCH_GATE_UNSAFE
        },
        Ordering::Release,
    );
}

fn cancel_smp_launch_and_wait(state_ptr: *const SmpLaunchState) -> bool {
    let state = unsafe { &*state_ptr };
    let phase = state.cancel_launch();
    if phase != LAUNCH_GATE_CLAIMED {
        return phase != LAUNCH_GATE_UNSAFE;
    }

    for _ in 0..SMP_LAUNCH_YIELD_LIMIT {
        match state.launch_gate.load(Ordering::Acquire) {
            LAUNCH_GATE_CLAIMED => smp_wait_delay(),
            LAUNCH_GATE_UNSAFE => return false,
            _ => return true,
        }
    }
    false
}

unsafe fn devirtualize_claimed_cpu(vcpu: *mut Vcpu, cpu: u32) -> bool {
    if !is_virtualized() {
        return true;
    }

    match (&*vcpu).devirtualize_cpu() {
        Ok(()) if !is_virtualized() => true,
        Ok(()) => {
            log::error!(
                "CPU {} still reports VMX active after claimed-launch teardown",
                cpu
            );
            false
        }
        Err(error) => {
            log::error!(
                "Failed to devirtualize CPU {} while resolving claimed launch: {:?}",
                cpu,
                error
            );
            false
        }
    }
}

fn terminate_system_thread() -> ! {
    unsafe {
        let _ = PsTerminateSystemThread(STATUS_SUCCESS);
    }
    // PsTerminateSystemThread does not return on success. Do not let an
    // unexpected status resume a worker whose owner assumes it is gone.
    loop {
        core::hint::spin_loop();
    }
}

/// Retain the affinity guard until every CPU is native. Reverting affinity
/// from an already-native CPU while peers still run non-root recreates the
/// same scheduler window as launch, in reverse.
fn park_pinned_worker(
    state: &SmpLaunchState,
    executor: ProcessorExecutor,
    cpu: u32,
) -> ! {
    while !state.stop.load(Ordering::Acquire) {
        if !state.wait_for_stop() {
            smp_wait_delay();
        }
    }
    diag::set_boot_stage(880 + cpu as u64);
    drop(executor);
    terminate_system_thread()
}

/// A successful VMLAUNCH returns in guest mode on the pinned system thread.
/// Wait for teardown, execute VMXOFF on that same CPU, then retain affinity
/// until the owner confirms every CPU has left VMX.
fn park_virtualized_worker(
    state: &SmpLaunchState,
    executor: ProcessorExecutor,
    vcpu: *mut Vcpu,
    cpu: u32,
) -> ! {
    // Monotonic per-CPU park: 700 + 3*cpu + 2 (see diag::launch_stage_band).
    // Old 770+cpu hid later CPUs' VMLAUNCH (701..) under peak 770 after CPU0 park.
    diag::set_boot_stage(diag::launch_stage_band(cpu, diag::LAUNCH_PHASE_PARK));
    if !state.wait_for_launch(cpu) {
        state.teardown_failed.store(true, Ordering::Release);
        mark_virtualization_failure(cpu);
    }

    let safe = unsafe { devirtualize_claimed_cpu(vcpu, cpu) };
    if !safe {
        state.teardown_failed.store(true, Ordering::Release);
        mark_virtualization_failure(cpu);
    }
    park_pinned_worker(state, executor, cpu)
}

unsafe extern "C" fn smp_launch_thread(start_context: PVOID) {
    if start_context.is_null() {
        terminate_system_thread();
    }

    let context = Box::from_raw(start_context as *mut SmpLaunchContext);
    let state_ptr = context.state;
    let vcpu = context.vcpu;
    let shared_data = context.shared_data;
    let cpu = context.cpu_index;
    drop(context);
    let state = &*state_ptr;

    // Keep pinned-worker progress below the 700+ launch band. The stage value
    // encodes the target LP even before the thread reaches that processor.
    diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_BIND));

    // Pin every worker while the entire machine is still native. A worker
    // blocks on its private dispatcher event after publishing READY, so this
    // does not recreate the old runnable-waiter herd.
    diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_BIND));
    if state.aborted() {
        terminate_system_thread();
    }
    let Some(executor) = ProcessorExecutor::switch_to_processor(cpu) else {
        diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_BIND));
        mark_virtualization_failure(cpu);
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        terminate_system_thread();
    };
    diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_PREFLIGHT));
    if current_processor_index() != cpu {
        diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_PREFLIGHT));
        mark_virtualization_failure(cpu);
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        park_pinned_worker(state, executor, cpu);
    }

    // Validate this exact LP while every processor is still native. Any
    // heterogeneous capability mismatch aborts before the launch barrier.
    diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_PREFLIGHT));
    if let Err(error) = Vmxon::preflight().and_then(|()| Vmcs::preflight_vmcs_control_fields()) {
        log::error!("VMX preflight failed on CPU {}: {:?}", cpu, error);
        mark_virtualization_failure(cpu);
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        park_pinned_worker(state, executor, cpu);
    }

    state.ready.fetch_add(1, Ordering::Release);
    diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_READY));
    if !state.wait_for_launch(cpu) {
        diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_READY));
        mark_virtualization_failure(cpu);
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        park_pinned_worker(state, executor, cpu);
    }
    if state.aborted() {
        park_pinned_worker(state, executor, cpu);
    }
    diag::set_boot_stage(prelaunch_stage_band(cpu, PRELAUNCH_PHASE_READY));

    // The owner opens and signals exactly one per-CPU gate at a time. Check
    // both the logical turn and the cancellation gate before entering VMX.
    if !state.has_launch_turn(cpu) {
        mark_virtualization_failure(cpu);
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        park_pinned_worker(state, executor, cpu);
    }
    if !state.claim_launch() {
        park_pinned_worker(state, executor, cpu);
    }
    if state.aborted() {
        mark_launch_terminal(state, true);
        park_pinned_worker(state, executor, cpu);
    }

    // 690 = worker on target LP, about to capture/VMXON (Vmx::run reuses 700
    // immediately before the VMLAUNCH instruction).
    diag::set_boot_stage(690 + cpu as u64);
    // Complete VMX storage was installed in this VCPU on the BSP. Target-CPU
    // capture and setup below do not allocate or release backing memory.
    let result = (&mut *vcpu).virtualize_cpu_prealloc(&*shared_data);
    if let Err(error) = result {
        // Preserve BootStageStop as a clean abort (isolation builds); do not
        // treat intentional stage stops as a hard virtualization failure that
        // only surfaces as ProcessorSwitchFailed.
        let intentional_stop = matches!(&error, HypervisorError::BootStageStop);
        // VMXOFFFailed can return while this CPU is still in VMX root mode,
        // where the guest VMCALL teardown path is invalid. Fail closed and
        // keep the owner graph resident instead of attempting a second exit.
        let vmxoff_failed = matches!(&error, HypervisorError::VMXOFFFailed);
        let safe = if vmxoff_failed {
            false
        } else {
            devirtualize_claimed_cpu(vcpu, cpu)
        };
        mark_launch_terminal(state, safe);
        if intentional_stop {
            state.stage_stop.store(true, Ordering::Release);
        } else {
            mark_virtualization_failure(cpu);
        }
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        if !safe {
            state.teardown_failed.store(true, Ordering::Release);
        }
        park_pinned_worker(state, executor, cpu);
    }

    if !is_virtualized() {
        mark_launch_terminal(state, true);
        mark_virtualization_failure(cpu);
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        park_pinned_worker(state, executor, cpu);
    }

    // If cancellation raced VMLAUNCH, this pinned worker owns VMXOFF. The
    // parent waits for a terminal gate before it can touch VCPU storage.
    if state.aborted() {
        let safe = devirtualize_claimed_cpu(vcpu, cpu);
        mark_launch_terminal(state, safe);
        if !safe {
            mark_virtualization_failure(cpu);
            state.teardown_failed.store(true, Ordering::Release);
        }
        park_pinned_worker(state, executor, cpu);
    }

    // Guest return already wrote launch_stage_band(cpu, GUEST_RETURN). Do not
    // stamp 761+ here — that sat above park(702) and hid per-CPU park peaks.
    if !state.advance_launch_turn(cpu) {
        let safe = devirtualize_claimed_cpu(vcpu, cpu);
        mark_launch_terminal(state, safe);
        mark_virtualization_failure(cpu);
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        if !safe {
            state.teardown_failed.store(true, Ordering::Release);
        }
        park_pinned_worker(state, executor, cpu);
    }

    // ACTIVE is published only after every branch that can touch this VCPU.
    // Once the parent observes it, the worker only updates launch state and
    // parks until teardown.
    if !state.mark_launch_active() {
        let safe = devirtualize_claimed_cpu(vcpu, cpu);
        mark_launch_terminal(state, safe);
        mark_virtualization_failure(cpu);
        state.abort.store(true, Ordering::Release);
        state.signal_all_launch_workers();
        if !safe {
            state.teardown_failed.store(true, Ordering::Release);
        }
        park_pinned_worker(state, executor, cpu);
    }

    state.active.fetch_add(1, Ordering::Release);
    park_virtualized_worker(state, executor, vcpu, cpu);
}

fn wait_for_smp_ready(state_ptr: *const SmpLaunchState, expected: u32) -> bool {
    for _ in 0..SMP_LAUNCH_YIELD_LIMIT {
        let state = unsafe { &*state_ptr };
        if state.aborted() {
            return false;
        }
        if state.ready.load(Ordering::Acquire) >= expected {
            return true;
        }
        smp_wait_delay();
    }
    false
}

fn wait_for_smp_launch_turn_past(state_ptr: *const SmpLaunchState, cpu_index: u32) -> bool {
    for _ in 0..SMP_LAUNCH_YIELD_LIMIT {
        let state = unsafe { &*state_ptr };
        if state.aborted() {
            return false;
        }
        if state.launch_turn.load(Ordering::Acquire) > cpu_index
            && state.launch_gate.load(Ordering::Acquire) == LAUNCH_GATE_ACTIVE
        {
            return true;
        }
        smp_wait_delay();
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
        smp_wait_delay();
    }
    false
}

fn wait_for_smp_native(state_ptr: *const SmpLaunchState) -> bool {
    for _ in 0..SMP_LAUNCH_YIELD_LIMIT {
        let state = unsafe { &*state_ptr };
        if state.teardown_failed.load(Ordering::Acquire) {
            return false;
        }
        if virtualized_processor_count() == 0 {
            return true;
        }
        smp_wait_delay();
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

        if !launch_lifecycle_allows_start(
            self.launch_attempted,
            self.devirtualized,
            self.smp_state.is_some(),
            !self.smp_worker_handles.is_empty(),
        ) {
            log::error!("Refusing to reuse one-shot Hypervisor launch state");
            return Err(HypervisorError::ProcessorSwitchFailed);
        }

        // Quiesce local_diag disk flushes for the whole bring-up window.
        // Guard drops (and re-enables I/O) on every return path, success or fail.
        let _launch_io = diag::LaunchIoQuiesceGuard::enter();
        diag::boot_stage(290)?;

        if !skip_cpu_configuration_is_supported(SKIP_CPU_INDEX) {
            log::error!(
                "Refusing HV_SKIP_CPU={} because every active CPU must enter VMX",
                SKIP_CPU_INDEX
            );
            return Err(HypervisorError::VMXUnsupported);
        }

        // Preflight once on the current CPU only. Affinity-walking all LPs
        // (24–64) before SMP launch was itself a 0x101 risk and is redundant
        // on homogeneous client silicon. Per-CPU Vmx::new still fails clearly
        // if a later LP has incompatible controls.
        {
            let result = Vmxon::preflight().and_then(|()| Vmcs::preflight_vmcs_control_fields());
            result?;
        }

        diag::boot_stage(295)?;

        // VMLAUNCH captures the current guest continuation stack. Always use
        // the persistent worker path, including on a one-CPU machine, so the
        // captured stack never belongs to the expanded DriverEntry callout.
        self.launch_attempted = true;
        self.virtualize_processors_smp()
    }

    /// Launches one pinned worker per logical processor. Workers remain
    /// resident after the guest context returns so a live VMX CPU is never
    /// torn down by `PsTerminateSystemThread`.
    ///
    /// Workers are pinned one CPU at a time while every LP is still native,
    /// then block on private dispatcher events. Once all affinity transitions
    /// are complete, the owner releases one VMLAUNCH turn at a time. This
    /// avoids both the old runnable-waiter herd and affinity migration while
    /// the machine is only partially virtualized.
    fn virtualize_processors_smp(&mut self) -> Result<(), HypervisorError> {
        let count = self.processors.len() as u32;
        if count == 0 || count != processor_count() {
            return Err(HypervisorError::ProcessorSwitchFailed);
        }

        self.devirtualized = false;
        clear_virtualization_failures();
        let state = Box::new(SmpLaunchState::new(count));
        let state_ptr = state.as_ref() as *const SmpLaunchState;
        let processors_ptr = self.processors.as_mut_ptr();
        let shared_data_ptr = self.shared_data.as_ref() as *const SharedData;

        // Pre-allocate and install every LP's complete VMX owner graph on the
        // BSP **before** any VMLAUNCH. Allocating or freeing backing storage
        // under partially virtualized SMP can stall scheduler progress.
        // SMP orchestration stages stay in 350..399 so Ext CMOS *peak* can
        // still advance through worker 68x / VMLAUNCH 700 / guest 75x.
        // (Old 2800/2900 numbers were higher than 700 and hid VMLAUNCH peaks.)
        diag::set_boot_stage(350);
        for processor in self.processors.iter_mut() {
            let prealloc = match crate::intel::vmx::VmxContigPrealloc::allocate() {
                Ok(prealloc) => prealloc,
                Err(_) => {
                    self.smp_state = Some(state);
                    return Err(HypervisorError::OutOfMemory);
                }
            };
            if processor.install_launch_prealloc(prealloc).is_err() {
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            }
        }

        if self
            .smp_worker_handles
            .try_reserve_exact(count as usize)
            .is_err()
        {
            self.smp_state = Some(state);
            return Err(HypervisorError::OutOfMemory);
        }

        // Build every fallible context allocation before publishing state_ptr
        // to a kernel thread. Taking an Option below only moves a Box.
        let mut launch_contexts: Vec<Option<Box<SmpLaunchContext>>> = Vec::new();
        if launch_contexts.try_reserve_exact(count as usize).is_err() {
            self.smp_state = Some(state);
            return Err(HypervisorError::OutOfMemory);
        }
        for index in 0..count {
            let context = match Box::try_new(SmpLaunchContext {
                vcpu: unsafe { processors_ptr.add(index as usize) },
                shared_data: shared_data_ptr,
                state: state_ptr,
                cpu_index: index,
            }) {
                Ok(context) => context,
                Err(_) => {
                    self.smp_state = Some(state);
                    return Err(HypervisorError::OutOfMemory);
                }
            };
            launch_contexts.push(Some(context));
        }

        // Phase 1: create and pin every worker before the first VMXON. Wait for
        // each worker to publish READY before creating the next one, keeping
        // affinity changes serialized without leaving runnable pollers.
        for index in 0..count {
            if unsafe { (*state_ptr).aborted() } {
                let _ = cancel_smp_launch_and_wait(state_ptr);
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            }

            diag::set_boot_stage(360 + index as u64);
            let Some(context) = launch_contexts[index as usize].take() else {
                unsafe {
                    (*state_ptr).abort.store(true, Ordering::Release);
                }
                let _ = cancel_smp_launch_and_wait(state_ptr);
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            };
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
                let _ = cancel_smp_launch_and_wait(state_ptr);
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            }
            self.smp_worker_handles.push(handle);

            diag::set_boot_stage(370 + index as u64);
            if !wait_for_smp_ready(state_ptr, index + 1) {
                let _ = cancel_smp_launch_and_wait(state_ptr);
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            }
        }

        let ready = unsafe { (*state_ptr).ready.load(Ordering::Acquire) };
        if !launch_barrier_is_safe(ready, count, virtualized_processor_count()) {
            let _ = cancel_smp_launch_and_wait(state_ptr);
            self.smp_state = Some(state);
            return Err(HypervisorError::ProcessorSwitchFailed);
        }
        diag::set_boot_stage(PRELAUNCH_BARRIER_COMPLETE_STAGE);

        // Phase 2: every affinity API has returned and every worker is asleep
        // on its target LP. Release only the current launch turn.
        for index in 0..count {
            if unsafe { (*state_ptr).aborted() } {
                let _ = cancel_smp_launch_and_wait(state_ptr);
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            }

            if !unsafe { (*state_ptr).prepare_launch(index == 0) } {
                let cleanup_safe = cancel_smp_launch_and_wait(state_ptr);
                if !cleanup_safe {
                    log::error!(
                        "Launch gate could not be cancelled safely before CPU {} release",
                        index
                    );
                }
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            }

            diag::set_boot_stage(380 + index as u64);
            if !unsafe { (*state_ptr).signal_launch_worker(index) } {
                let _ = cancel_smp_launch_and_wait(state_ptr);
                self.smp_state = Some(state);
                return Err(HypervisorError::ProcessorSwitchFailed);
            }

            if !wait_for_smp_launch_turn_past(state_ptr, index) {
                let cleanup_safe = cancel_smp_launch_and_wait(state_ptr);
                if !cleanup_safe {
                    log::error!(
                        "CPU {} launch did not reach a cleanup-safe terminal state",
                        index
                    );
                }
                let stage_stop = unsafe { (*state_ptr).stage_stop.load(Ordering::Acquire) };
                self.smp_state = Some(state);
                return Err(if stage_stop {
                    HypervisorError::BootStageStop
                } else {
                    HypervisorError::ProcessorSwitchFailed
                });
            }

            if index + 1 < count {
                let mut interval = LARGE_INTEGER {
                    QuadPart: SMP_INTER_CPU_SETTLE_100NS,
                };
                unsafe {
                    let _ = KeDelayExecutionThread(_MODE::KernelMode as _, 0, &mut interval);
                }
            }
        }

        if !wait_for_smp_active(state_ptr, count) {
            let cleanup_safe = cancel_smp_launch_and_wait(state_ptr);
            if !cleanup_safe {
                log::error!("SMP launch did not reach a cleanup-safe terminal state");
            }
            let stage_stop = unsafe { (*state_ptr).stage_stop.load(Ordering::Acquire) };
            self.smp_state = Some(state);
            return Err(if stage_stop {
                HypervisorError::BootStageStop
            } else {
                HypervisorError::ProcessorSwitchFailed
            });
        }

        self.smp_state = Some(state);
        Ok(())
    }

    fn stop_smp_workers(&mut self) -> bool {
        let Some(state) = self.smp_state.as_ref() else {
            return self.smp_worker_handles.is_empty();
        };

        state.stop.store(true, Ordering::Release);
        // Wake both workers still waiting for a launch/cancel token and
        // workers parked after VMXOFF. stop_event is notification-style, so a
        // late arriver also observes the release.
        state.signal_all_launch_workers();
        state.signal_stop();
        let mut all_stopped = true;
        for handle in &mut self.smp_worker_handles {
            if handle.is_null() {
                continue;
            }

            let mut timeout = LARGE_INTEGER {
                QuadPart: SMP_WORKER_WAIT_TIMEOUT_100NS,
            };
            let wait_status = unsafe { ZwWaitForSingleObject(*handle, false as _, &mut timeout) };
            // STATUS_TIMEOUT (0x102) is non-negative, so NT_SUCCESS would
            // incorrectly treat a still-running worker as signaled and let
            // its SmpLaunchState/Vcpu storage be freed underneath it.
            if !smp_worker_wait_completed(wait_status) {
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

        if let Some(state) = self.smp_state.as_ref() {
            let state_ptr = state.as_ref() as *const SmpLaunchState;
            if !cancel_smp_launch_and_wait(state_ptr) || state.cleanup_is_blocked() {
                log::error!(
                    "Refusing cleanup while an SMP launch is claimed or VMX state is unsafe"
                );
                return Err(HypervisorError::ProcessorSwitchFailed);
            }

            // Pinned workers execute VMXOFF on the same CPUs that launched
            // them. Do not affinity-walk the owner through a reverse partial-
            // virtualization window.
            if !wait_for_smp_native(state_ptr) {
                log::error!("Pinned SMP teardown did not return every CPU to native mode");
                return Err(HypervisorError::ProcessorSwitchFailed);
            }
            mark_launch_terminal(state, true);
            if !self.stop_smp_workers() {
                return Err(HypervisorError::ProcessorSwitchFailed);
            }
            self.devirtualized = true;
            return Ok(());
        }

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

        if let Some(state) = self.smp_state.as_ref() {
            mark_launch_terminal(state, true);
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

/// Optional build-time cap on virtualized LPs (`HV_MAX_CPUS=N`). 0 / unset = all.
const MAX_CPUS: u32 = parse_max_cpus(option_env!("HV_MAX_CPUS"));

const fn parse_max_cpus(value: Option<&str>) -> u32 {
    let Some(value) = value else {
        return 0;
    };
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let mut i = 0;
    let mut parsed = 0u32;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte < b'0' || byte > b'9' {
            return 0;
        }
        parsed = parsed.saturating_mul(10).saturating_add((byte - b'0') as u32);
        i += 1;
    }
    parsed
}

fn configured_processor_count(total: u32, configured_max: u32) -> Option<u32> {
    if total == 0 {
        None
    } else if configured_max == 0 || configured_max >= total {
        Some(total)
    } else {
        None
    }
}

fn effective_processor_count() -> Result<u32, HypervisorError> {
    configured_processor_count(processor_count(), MAX_CPUS)
        .ok_or(HypervisorError::ProcessorSwitchFailed)
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

fn skip_cpu_configuration_is_supported(skip_cpu: u32) -> bool {
    skip_cpu == NO_SKIP_CPU
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
                IDENTITY_CR3.store(0, Ordering::Release);
                ManuallyDrop::drop(&mut self.processors);
                ManuallyDrop::drop(&mut self.shared_data);
                ManuallyDrop::drop(&mut self.identity_paging);
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
    fn smp_worker_wait_requires_a_signaled_object() {
        assert!(smp_worker_wait_completed(STATUS_SUCCESS));
        assert!(!smp_worker_wait_completed(0x102));
        assert!(!smp_worker_wait_completed(-1));
    }

    #[test]
    fn skip_cpu_parser_accepts_decimal_only() {
        assert_eq!(parse_skip_cpu(None), NO_SKIP_CPU);
        assert_eq!(parse_skip_cpu(Some("")), NO_SKIP_CPU);
        assert_eq!(parse_skip_cpu(Some("8")), 8);
        assert_eq!(parse_skip_cpu(Some("8x")), NO_SKIP_CPU);
    }

    #[test]
    fn skip_cpu_configuration_is_always_rejected() {
        assert!(skip_cpu_configuration_is_supported(NO_SKIP_CPU));
        assert!(!skip_cpu_configuration_is_supported(0));
        assert!(!skip_cpu_configuration_is_supported(8));
    }

    #[test]
    fn processor_count_rejects_persistent_partial_virtualization() {
        assert_eq!(configured_processor_count(64, 0), Some(64));
        assert_eq!(configured_processor_count(64, 64), Some(64));
        assert_eq!(configured_processor_count(64, 128), Some(64));
        assert_eq!(configured_processor_count(64, 1), None);
        assert_eq!(configured_processor_count(64, 63), None);
        assert_eq!(configured_processor_count(0, 0), None);
    }

    #[test]
    fn smp_launch_turn_advances_exactly_once_per_cpu() {
        let state = SmpLaunchState::new(0);
        assert!(state.has_launch_turn(0));
        assert!(!state.has_launch_turn(1));
        assert!(state.advance_launch_turn(0));
        assert!(!state.advance_launch_turn(0));
        assert!(state.has_launch_turn(1));
        assert!(state.advance_launch_turn(1));
        assert!(state.has_launch_turn(2));
    }

    #[test]
    fn launch_gate_serializes_each_cpu_claim() {
        let state = SmpLaunchState::new(0);
        assert!(state.prepare_launch(true));
        assert!(state.claim_launch());
        assert!(state.cleanup_is_blocked());
        assert!(state.mark_launch_active());
        assert!(!state.cleanup_is_blocked());

        assert!(state.prepare_launch(false));
        assert!(state.claim_launch());
        mark_launch_terminal(&state, true);
        assert!(!state.cleanup_is_blocked());
    }

    #[test]
    fn launch_gate_cancellation_wins_before_claim() {
        let state = SmpLaunchState::new(0);
        assert_eq!(state.cancel_launch(), LAUNCH_GATE_CANCELLED);
        assert!(!state.claim_launch());
        assert!(state.aborted());
        assert!(!state.cleanup_is_blocked());
    }

    #[test]
    fn launch_gate_blocks_cleanup_until_claim_is_terminal() {
        let state = SmpLaunchState::new(0);
        assert!(state.claim_launch());
        assert_eq!(state.cancel_launch(), LAUNCH_GATE_CLAIMED);
        assert!(state.cleanup_is_blocked());

        mark_launch_terminal(&state, false);
        assert!(state.cleanup_is_blocked());
        assert_eq!(state.cancel_launch(), LAUNCH_GATE_UNSAFE);

        mark_launch_terminal(&state, true);
        assert!(!state.cleanup_is_blocked());
    }

    #[test]
    fn launch_barrier_requires_every_worker_and_no_vmx_cpu() {
        assert!(launch_barrier_is_safe(24, 24, 0));
        assert!(!launch_barrier_is_safe(23, 24, 0));
        assert!(!launch_barrier_is_safe(24, 24, 1));
        assert!(!launch_barrier_is_safe(0, 0, 0));
    }

    #[test]
    fn prelaunch_diagnostics_never_enter_the_vmx_launch_band() {
        assert_eq!(prelaunch_stage_band(0, PRELAUNCH_PHASE_BIND), 624);
        assert_eq!(prelaunch_stage_band(23, PRELAUNCH_PHASE_READY), 695);
        assert_eq!(prelaunch_stage_band(24, PRELAUNCH_PHASE_READY), 695);
        assert!(prelaunch_stage_band(u32::MAX, u64::MAX) < 700);
        assert!(PRELAUNCH_BARRIER_COMPLETE_STAGE < 700);
    }

    #[test]
    fn hypervisor_launch_state_is_one_shot() {
        assert!(launch_lifecycle_allows_start(false, true, false, false));
        assert!(!launch_lifecycle_allows_start(true, true, false, false));
        assert!(!launch_lifecycle_allows_start(false, false, false, false));
        assert!(!launch_lifecycle_allows_start(false, true, true, false));
        assert!(!launch_lifecycle_allows_start(false, true, false, true));
    }

    #[test]
    fn launch_events_release_only_the_selected_worker() {
        let state = SmpLaunchState::new(2);
        assert!(state.signal_launch_worker(1));
        assert!(!state.wait_for_launch(0));
        assert!(state.wait_for_launch(1));
        assert!(!state.wait_for_launch(1));
        assert!(!state.signal_launch_worker(2));
    }
}
