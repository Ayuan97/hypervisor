use {
    core::{
        fmt::{self, Write},
        mem::{size_of, zeroed},
        ptr::null_mut,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    },
    hypervisor::intel::{client_read, diag, terminal_capture},
    wdk_sys::{
        ntddk::{
            KeDelayExecutionThread, PsCreateSystemThread, PsTerminateSystemThread, ZwClose,
            ZwCreateFile, ZwFlushBuffersFile, ZwWaitForSingleObject, ZwWriteFile,
        },
        FILE_ATTRIBUTE_NORMAL, FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT, GENERIC_WRITE, HANDLE,
        IO_STATUS_BLOCK, LARGE_INTEGER, NT_SUCCESS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE,
        OBJ_KERNEL_HANDLE, PVOID, STATUS_SUCCESS, SYNCHRONIZE, THREAD_ALL_ACCESS, UNICODE_STRING,
        _MODE,
    },
};

const WORKER_DELAY_100NS: i64 = -1_000_000; // 100 ms
/// Skip disk entirely for this many ticks after worker start (post-VMLAUNCH settle).
/// 30 × 100 ms = 3 s — hybrid single-LP was still 0x101-sensitive with 500 ms.
const WORKER_SETTLE_TICKS: u64 = 30;
/// Only ZwFlushBuffersFile every N ticks after settle (cuts TLB shootdown rate).
const WORKER_FLUSH_EVERY_TICKS: u64 = 20;
const CPU_RECORDS_PER_TICK: usize = 16;
const LOG_PATH_DISPLAY: &str = r"D:\cheat\hv_diag_live.log";
static LOG_PATH_UTF16: &[u16] = &[
    '\\' as u16,
    '?' as u16,
    '?' as u16,
    '\\' as u16,
    'D' as u16,
    ':' as u16,
    '\\' as u16,
    'c' as u16,
    'h' as u16,
    'e' as u16,
    'a' as u16,
    't' as u16,
    '\\' as u16,
    'h' as u16,
    'v' as u16,
    '_' as u16,
    'd' as u16,
    'i' as u16,
    'a' as u16,
    'g' as u16,
    '_' as u16,
    'l' as u16,
    'i' as u16,
    'v' as u16,
    'e' as u16,
    '.' as u16,
    'l' as u16,
    'o' as u16,
    'g' as u16,
    0,
];
const CMOS_CAPTURE_PATH_DISPLAY: &str = r"D:\cheat\hv_cmos_capture.txt";
static CMOS_CAPTURE_PATH_UTF16: &[u16] = &[
    '\\' as u16,
    '?' as u16,
    '?' as u16,
    '\\' as u16,
    'D' as u16,
    ':' as u16,
    '\\' as u16,
    'c' as u16,
    'h' as u16,
    'e' as u16,
    'a' as u16,
    't' as u16,
    '\\' as u16,
    'h' as u16,
    'v' as u16,
    '_' as u16,
    'c' as u16,
    'm' as u16,
    'o' as u16,
    's' as u16,
    '_' as u16,
    'c' as u16,
    'a' as u16,
    'p' as u16,
    't' as u16,
    'u' as u16,
    'r' as u16,
    'e' as u16,
    '.' as u16,
    't' as u16,
    'x' as u16,
    't' as u16,
    0,
];

static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static WORKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static WORKER_HANDLE: AtomicU64 = AtomicU64::new(0);
static LOG_HANDLE: AtomicU64 = AtomicU64::new(0);
static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static WRITE_FAILURES: AtomicU64 = AtomicU64::new(0);
static DROPPED_RECORDS: AtomicU64 = AtomicU64::new(0);
static TERMINAL_WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static TERMINAL_WORKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static TERMINAL_WORKER_HANDLE: AtomicU64 = AtomicU64::new(0);

const fn enabled_by_build_flag(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 1 && bytes[0] == b'1'
}

pub fn enabled_by_build() -> bool {
    enabled_by_build_flag(option_env!("HV_LOCAL_DIAG")) && !terminal_capture::enabled()
}

const fn terminal_capture_by_build() -> bool {
    enabled_by_build_flag(option_env!("HV_TERMINAL_CAPTURE"))
}

/// Persist one read-only snapshot of extended CMOS and synchronously flush it.
/// This path does not use the periodic worker or the VMX launch I/O gate.
pub fn write_cmos_capture(bytes: &[u8; terminal_capture::CMOS_BYTES]) -> bool {
    let mut output = FixedBuffer::<512>::new();
    if !format_cmos_capture(bytes, &mut output) {
        return false;
    }

    let Some(handle) = open_output_file(CMOS_CAPTURE_PATH_UTF16) else {
        return false;
    };
    let written = write_handle_bytes(handle, output.as_bytes(), true);
    let closed = unsafe { NT_SUCCESS(ZwClose(handle)) };
    written && closed
}

fn format_cmos_capture(
    bytes: &[u8; terminal_capture::CMOS_BYTES],
    output: &mut FixedBuffer<512>,
) -> bool {
    if writeln!(
        output,
        "HVCMOS1 version=1 bytes={} source=ext_cmos index_port=0x72 data_port=0x73 read_only=1 path={}",
        terminal_capture::CMOS_BYTES,
        CMOS_CAPTURE_PATH_DISPLAY
    )
    .is_err()
        || output.write_str("raw_hex=").is_err()
    {
        return false;
    }
    for byte in bytes {
        if write!(output, "{:02x}", byte).is_err() {
            return false;
        }
    }
    writeln!(output).is_ok()
}

/// Open the log and write HVL1 START before any VMX bring-up.
/// Does **not** start the periodic worker — call [`start_worker_if_enabled`]
/// only after virtualization succeeds so ZwFlushBuffersFile cannot race SMP
/// launch (0x101).
///
/// START is written **without** `ZwFlushBuffersFile`. Explicit flush during
/// load was a repeated 0x101 witness (`NtFlushBuffersFile` →
/// `KeFlushMultipleRangeTb`). The first post-launch worker flush commits it.
pub fn prepare_log_if_enabled() -> bool {
    if !enabled_by_build() {
        return true;
    }
    if LOG_HANDLE.load(Ordering::Acquire) != 0 {
        return true;
    }

    let Some(log_handle) = open_log_file() else {
        return false;
    };
    LOG_HANDLE.store(log_handle as u64, Ordering::Release);
    if !write_start_record() || !write_prev_boot_records() {
        close_log_file();
        return false;
    }
    true
}

/// Start the 100 ms telemetry thread. Requires [`prepare_log_if_enabled`] first
/// (or opens the log itself if prepare was skipped).
pub fn start_worker_if_enabled() -> bool {
    if terminal_capture::terminal_mode() {
        return start_terminal_worker_if_enabled();
    }
    if !enabled_by_build() || WORKER_STARTED.load(Ordering::Acquire) {
        return true;
    }

    if LOG_HANDLE.load(Ordering::Acquire) == 0 {
        if !prepare_log_if_enabled() {
            return false;
        }
    }

    WORKER_SHUTDOWN.store(false, Ordering::Release);

    let mut thread_handle: HANDLE = null_mut();
    let status = unsafe {
        PsCreateSystemThread(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            null_mut(),
            Some(worker_main),
            null_mut(),
        )
    };
    if !NT_SUCCESS(status) {
        close_log_file();
        return false;
    }

    WORKER_HANDLE.store(thread_handle as u64, Ordering::Release);
    WORKER_STARTED.store(true, Ordering::Release);
    true
}

pub fn stop_worker() -> bool {
    if terminal_capture::terminal_mode() {
        return stop_terminal_worker();
    }
    WORKER_SHUTDOWN.store(true, Ordering::Release);
    let thread_handle = WORKER_HANDLE.load(Ordering::Acquire) as HANDLE;
    if thread_handle.is_null() {
        WORKER_STARTED.store(false, Ordering::Release);
        return close_log_file();
    }

    let thread_closed = unsafe {
        if !NT_SUCCESS(ZwWaitForSingleObject(
            thread_handle,
            false as _,
            null_mut(),
        )) {
            return false;
        }
        NT_SUCCESS(ZwClose(thread_handle))
    };
    WORKER_HANDLE.store(0, Ordering::Release);
    WORKER_STARTED.store(false, Ordering::Release);
    close_log_file() && thread_closed
}

/// Start the terminal flight-recorder worker. This thread performs no file
/// I/O; its sole periodic action is the reboot-persistent CMOS checkpoint.
pub fn start_terminal_worker_if_enabled() -> bool {
    if !terminal_capture_by_build()
        || TERMINAL_WORKER_STARTED.load(Ordering::Acquire)
    {
        return true;
    }

    TERMINAL_WORKER_SHUTDOWN.store(false, Ordering::Release);
    let mut thread_handle: HANDLE = null_mut();
    let status = unsafe {
        PsCreateSystemThread(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            null_mut(),
            Some(terminal_worker_main),
            null_mut(),
        )
    };
    if !NT_SUCCESS(status) || thread_handle.is_null() {
        return false;
    }

    TERMINAL_WORKER_HANDLE.store(thread_handle as u64, Ordering::Release);
    TERMINAL_WORKER_STARTED.store(true, Ordering::Release);
    true
}

pub fn stop_terminal_worker() -> bool {
    TERMINAL_WORKER_SHUTDOWN.store(true, Ordering::Release);
    let thread_handle = TERMINAL_WORKER_HANDLE.load(Ordering::Acquire) as HANDLE;
    if thread_handle.is_null() {
        TERMINAL_WORKER_STARTED.store(false, Ordering::Release);
        return true;
    }

    let waited = unsafe {
        NT_SUCCESS(ZwWaitForSingleObject(
            thread_handle,
            false as _,
            null_mut(),
        ))
    };
    let closed = if waited {
        unsafe { NT_SUCCESS(ZwClose(thread_handle)) }
    } else {
        false
    };
    if waited {
        TERMINAL_WORKER_HANDLE.store(0, Ordering::Release);
        TERMINAL_WORKER_STARTED.store(false, Ordering::Release);
    }
    waited && closed
}

unsafe extern "C" fn terminal_worker_main(_context: PVOID) {
    while !TERMINAL_WORKER_SHUTDOWN.load(Ordering::Acquire) {
        // Keep this loop deliberately boring: all terminal evidence writes
        // happen inside the bounded CMOS checkpoint implementation.
        let _ = terminal_capture::periodic_checkpoint();
        let mut interval = LARGE_INTEGER {
            QuadPart: -10_000_000, // 1000 ms
        };
        let _ = KeDelayExecutionThread(_MODE::KernelMode as _, 0, &mut interval);
    }
    TERMINAL_WORKER_STARTED.store(false, Ordering::Release);
    let _ = PsTerminateSystemThread(STATUS_SUCCESS);
}

unsafe extern "C" fn worker_main(_context: PVOID) {
    let mut next_ring_index = [0u64; diag::MAX_TRACKED_CPUS];
    for (cpu, next) in next_ring_index.iter_mut().enumerate() {
        let current = diag::per_cpu_ring_idx(cpu as u64);
        *next = current.saturating_sub(1);
    }

    let mut next_cpu = 0usize;
    let mut tick = 0u64;
    let mut was_quiesced = false;
    let mut emitted_resume_mark = false;
    while !WORKER_SHUTDOWN.load(Ordering::Acquire) {
        let quiesced = diag::launch_io_quiesced();
        if quiesced {
            // SMP / preflight critical section: do not touch the filesystem.
            // KeFlushMultipleRangeTb from ZwFlushBuffersFile deadlocks with a
            // CPU mid-VMX bring-up (BSOD 0x101 CLOCK_WATCHDOG_TIMEOUT).
            was_quiesced = true;
            tick = tick.wrapping_add(1);
            delay_worker();
            continue;
        }

        // Brief settle after VMLAUNCH / after quiesce lifts before any disk I/O.
        if tick < WORKER_SETTLE_TICKS {
            tick = tick.wrapping_add(1);
            delay_worker();
            continue;
        }

        let mut batch = FixedBuffer::<4096>::new();
        // After launch quiesce ends, emit one explicit marker so the log shows
        // the critical section completed (and any suppressed write count).
        if was_quiesced && !emitted_resume_mark {
            was_quiesced = false;
            emitted_resume_mark = true;
            let mut mark = FixedBuffer::<256>::new();
            let _ = writeln!(
                mark,
                "HVL1 Q seq={} event=launch_io_resume suppressed_writes={} boot_stage={}",
                next_sequence(),
                diag::launch_io_suppressed_writes(),
                diag::control(9)
            );
            let _ = batch.write_str(mark.as_str());
        } else if !emitted_resume_mark {
            // Quiesce never observed (e.g. worker started after outer drop):
            // still emit a one-shot post-launch marker with boot_stage.
            emitted_resume_mark = true;
            let mut mark = FixedBuffer::<256>::new();
            let _ = writeln!(
                mark,
                "HVL1 Q seq={} event=worker_start suppressed_writes={} boot_stage={}",
                next_sequence(),
                diag::launch_io_suppressed_writes(),
                diag::control(9)
            );
            let _ = batch.write_str(mark.as_str());
        }
        next_cpu = append_ring_updates(&mut batch, &mut next_ring_index, next_cpu);
        if tick % 10 == 0 {
            append_counter_snapshot(&mut batch);
        }
        if !batch.as_bytes().is_empty() {
            // Flush sparingly: every write used to ZwFlushBuffersFile and IPI
            // all LPs (0x101 under load). Always flush the post-launch marker.
            let flush = batch.as_str().contains("HVL1 Q")
                || (tick % WORKER_FLUSH_EVERY_TICKS == 0);
            write_bytes(batch.as_bytes(), flush);
        }
        tick = tick.wrapping_add(1);
        delay_worker();
    }

    let mut stop = FixedBuffer::<256>::new();
    let _ = writeln!(
        stop,
        "HVL1 STOP seq={} write_failures={} dropped_records={}",
        next_sequence(),
        WRITE_FAILURES.load(Ordering::Relaxed),
        DROPPED_RECORDS.load(Ordering::Relaxed)
    );
    write_bytes(stop.as_bytes(), true);
    WORKER_STARTED.store(false, Ordering::Release);
    let _ = PsTerminateSystemThread(STATUS_SUCCESS);
}

fn write_start_record() -> bool {
    let mut start = FixedBuffer::<512>::new();
    let prev = diag::prev_boot_stage().unwrap_or(u64::MAX);
    let prev_cpu = diag::PREV_BOOT_STAGE_CPU.load(Ordering::Relaxed);
    let formatted = writeln!(
        start,
        "HVL1 START seq={} path={} cpus={} ring_size={} period_ms=100 boot_stage={} prev_boot_stage={} prev_boot_cpu={}",
        next_sequence(),
        LOG_PATH_DISPLAY,
        diag::MAX_TRACKED_CPUS,
        diag::PER_CPU_RING_SIZE,
        diag::control(9),
        prev,
        prev_cpu
    )
    .is_ok();
    // No ZwFlushBuffersFile here — see prepare_log_if_enabled docs.
    formatted && write_bytes(start.as_bytes(), false)
}

/// Persist a launch failure only after all processors are confirmed native and
/// the launch I/O quiesce guard has been released.
pub fn write_failure_record(status: i32) -> bool {
    if !enabled_by_build() {
        return true;
    }

    let ring_idx = diag::ring_current_idx();
    let ring_slot = ring_idx.wrapping_sub(1) % diag::RING_SIZE as u64;
    let mut failure = FixedBuffer::<3072>::new();
    let formatted = writeln!(
        failure,
        concat!(
            "HVL1 FAIL seq={} status=0x{:x} boot_stage={} exit=0x{:x} ",
            "handler={} detail=0x{:x} vm_kind={} vm_error=0x{:x} ",
            "entry_info=0x{:x} guest_intr=0x{:x} guest_activity=0x{:x} ",
            "guest_pending_dbg=0x{:x} ctl_pin=0x{:x} ctl_pri=0x{:x} ",
            "ctl_sec=0x{:x} ctl_exit=0x{:x} ctl_entry=0x{:x} ",
            "init={} sipi={} awaiting_sipi=0x{:x} init_stage={} init_stage_count={} ",
            "init_last_cpu={} sipi_vector={} ",
            "cpu0_count={} cpu0_reason=0x{:x} cpu0_rip=0x{:x} ",
            "cpu0_rsp=0x{:x} cpu0_rflags=0x{:x} cpu0_detail=0x{:x} ",
            "ring_idx={} ring_reason=0x{:x} ring_rip=0x{:x} ",
            "ring_qual=0x{:x} ring_rax=0x{:x}"
        ),
        next_sequence(),
        status as u32,
        diag::control(9),
        diag::control(6),
        diag::counter(17),
        diag::counter(18),
        diag::LAST_VM_INSTRUCTION_KIND.load(Ordering::Relaxed),
        diag::LAST_VM_INSTRUCTION_ERROR.load(Ordering::Relaxed),
        diag::LAST_VMENTRY_INTERRUPTION_INFO.load(Ordering::Relaxed),
        diag::LAST_GUEST_INTERRUPTIBILITY.load(Ordering::Relaxed),
        diag::LAST_GUEST_ACTIVITY_STATE.load(Ordering::Relaxed),
        diag::LAST_GUEST_PENDING_DEBUG.load(Ordering::Relaxed),
        diag::control(0),
        diag::control(1),
        diag::control(2),
        diag::control(3),
        diag::control(4),
        diag::control(280),
        diag::control(281),
        diag::control(282),
        diag::control(283),
        diag::control(284),
        diag::control(285),
        diag::control(286),
        diag::breadcrumb(0, diag::BREADCRUMB_FIELD_COUNT),
        diag::breadcrumb(0, diag::BREADCRUMB_FIELD_EXIT_REASON),
        diag::breadcrumb(0, diag::BREADCRUMB_FIELD_GUEST_RIP),
        diag::breadcrumb(0, diag::BREADCRUMB_FIELD_GUEST_RSP),
        diag::breadcrumb(0, diag::BREADCRUMB_FIELD_GUEST_RFLAGS),
        diag::breadcrumb(0, diag::BREADCRUMB_FIELD_DETAIL),
        ring_idx,
        diag::ring_entry(ring_slot, 0),
        diag::ring_entry(ring_slot, 1),
        diag::ring_entry(ring_slot, 2),
        diag::ring_entry(ring_slot, 3),
    )
    .is_ok();

    if !formatted {
        return false;
    }

    let vmcs_formatted = write!(
        failure,
        concat!(
            "HVL1 VMCS seq={} cr0=0x{:x} cr3=0x{:x} cr4=0x{:x} dr7=0x{:x} ",
            "rip=0x{:x} rsp=0x{:x} rflags=0x{:x} cs=0x{:x} ss=0x{:x} ",
            "ds=0x{:x} es=0x{:x} fs=0x{:x} gs=0x{:x} ldtr=0x{:x} tr=0x{:x} ",
            "cs_ar=0x{:x} ss_ar=0x{:x} ds_ar=0x{:x} es_ar=0x{:x} ",
            "fs_ar=0x{:x} gs_ar=0x{:x} ldtr_ar=0x{:x} tr_ar=0x{:x} ",
            "gdtr_base=0x{:x} gdtr_limit=0x{:x} idtr_base=0x{:x} ",
            "idtr_limit=0x{:x} efer=0x{:x} debugctl=0x{:x} ",
            "sysenter_cs=0x{:x} sysenter_esp=0x{:x} sysenter_eip=0x{:x}\n"
        ),
        next_sequence(),
        diag::vmcs_guest_state_field(0),
        diag::vmcs_guest_state_field(1),
        diag::vmcs_guest_state_field(2),
        diag::vmcs_guest_state_field(3),
        diag::vmcs_guest_state_field(4),
        diag::vmcs_guest_state_field(5),
        diag::vmcs_guest_state_field(6),
        diag::vmcs_guest_state_field(7),
        diag::vmcs_guest_state_field(8),
        diag::vmcs_guest_state_field(9),
        diag::vmcs_guest_state_field(10),
        diag::vmcs_guest_state_field(11),
        diag::vmcs_guest_state_field(12),
        diag::vmcs_guest_state_field(13),
        diag::vmcs_guest_state_field(14),
        diag::vmcs_guest_state_field(15),
        diag::vmcs_guest_state_field(16),
        diag::vmcs_guest_state_field(17),
        diag::vmcs_guest_state_field(18),
        diag::vmcs_guest_state_field(19),
        diag::vmcs_guest_state_field(20),
        diag::vmcs_guest_state_field(21),
        diag::vmcs_guest_state_field(22),
        diag::vmcs_guest_state_field(23),
        diag::vmcs_guest_state_field(24),
        diag::vmcs_guest_state_field(25),
        diag::vmcs_guest_state_field(26),
        diag::vmcs_guest_state_field(27),
        diag::vmcs_guest_state_field(28),
        diag::vmcs_guest_state_field(29),
        diag::vmcs_guest_state_field(30),
        diag::vmcs_guest_state_field(31),
    )
    .is_ok();

    vmcs_formatted && write_bytes(failure.as_bytes(), true)
}

/// Persist the previous boot's CMOS snapshots before this load can overwrite
/// them. This runs for every local-diag build, including stage-130 probes.
fn write_prev_boot_records() -> bool {
    let mut snapshot = FixedBuffer::<1024>::new();
    if write!(
        snapshot,
        "HVL1 PREV_SNAP seq={} valid={} global={}",
        next_sequence(),
        diag::control(140),
        diag::control(141)
    )
    .is_err()
    {
        return false;
    }
    for cpu in 0..diag::SNAP_MAX_CPUS {
        if write!(
            snapshot,
            " cpu{}={}:0x{:x}",
            cpu,
            diag::control(142 + cpu as u64),
            diag::control(166 + cpu as u64)
        )
        .is_err()
        {
            return false;
        }
    }
    if writeln!(snapshot).is_err() || !write_bytes(snapshot.as_bytes(), false) {
        return false;
    }

    // CTL 110 snapshots both Layer3 CMOS slots into the readout cache.
    let layer3_slot = diag::layer3_prepare_session();
    let mut fatal = FixedBuffer::<768>::new();
    if write!(
        fatal,
        concat!(
            "HVL1 PREV_FATAL seq={} step4=0x{:x} step4_arg0=0x{:x} ",
            "l3_slot={} l3_seq={} l3_port80=0x{:x} l3_bitmap=0x{:x} ",
            "l3_exit=0x{:x} l3_count={} l3_phase=0x{:x} l3_cr_phase=0x{:x} ",
            "l3_command=0x{:x} ",
            "l3_valid={} rare_valid={} ",
            "rare_head={} rare_count={}"
        ),
        next_sequence(),
        diag::cmos_read_step4(6),
        diag::cmos_read_step4(7),
        layer3_slot,
        diag::control(111),
        diag::control(112),
        diag::control(113),
        diag::control(114),
        diag::control(115),
        diag::control(118),
        diag::control(121),
        diag::control(119),
        diag::control(116),
        diag::control(240),
        diag::control(241),
        diag::control(242)
    )
    .is_err()
    {
        return false;
    }
    for slot in 0..diag::RARE_RING_SLOTS {
        let base = 243 + slot as u64 * 4;
        if write!(
            fatal,
            " rare{}={}:0x{:x}:0x{:x}:0x{:x}:0x{:x}",
            slot,
            diag::control(base),
            diag::control(base + 1),
            diag::control(base + 2),
            diag::control(276 + slot as u64),
            diag::control(287 + slot as u64)
        )
        .is_err()
        {
            return false;
        }
    }

    writeln!(fatal).is_ok() && write_bytes(fatal.as_bytes(), false)
}

fn append_ring_updates(
    batch: &mut FixedBuffer<4096>,
    next_ring_index: &mut [u64; diag::MAX_TRACKED_CPUS],
    start: usize,
) -> usize {
    let mut emitted = 0usize;
    let mut scanned = 0usize;
    let mut cpu = start;
    while scanned < diag::MAX_TRACKED_CPUS && emitted < CPU_RECORDS_PER_TICK {
        let current = diag::per_cpu_ring_idx(cpu as u64);
        let previous = next_ring_index[cpu];
        if current > previous {
            let sequence = current - 1;
            if let Some(entry) = diag::per_cpu_ring_snapshot(cpu, sequence) {
                let overwritten = current.saturating_sub(previous).saturating_sub(1);
                let mut line = FixedBuffer::<256>::new();
                let formatted = writeln!(
                    line,
                    concat!(
                        "HVL1 R seq={} cpu={} ring_seq={} overwritten={} ",
                        "reason=0x{:x} rip=0x{:x} qual=0x{:x} rax=0x{:x}"
                    ),
                    next_sequence(),
                    cpu,
                    entry.sequence,
                    overwritten,
                    entry.reason,
                    entry.rip,
                    entry.qualification,
                    entry.rax
                )
                .is_ok();
                if !formatted || batch.write_str(line.as_str()).is_err() {
                    DROPPED_RECORDS.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                next_ring_index[cpu] = current;
                emitted += 1;
            }
        }
        cpu = (cpu + 1) % diag::MAX_TRACKED_CPUS;
        scanned += 1;
    }
    cpu
}

fn append_counter_snapshot(batch: &mut FixedBuffer<4096>) {
    let event = diag::event_context_snapshot();
    let active = diag::handler_active_bitmap_lo();
    let active_cpu = if active == 0 {
        u64::MAX
    } else {
        active.trailing_zeros() as u64
    };
    let active_phase = if active_cpu == u64::MAX {
        0
    } else {
        diag::cpu_diag(active_cpu, 1)
    };
    let active_leaf = if active_cpu == u64::MAX {
        0
    } else {
        diag::cpu_diag(active_cpu, 2)
    };
    let active_command = if active_cpu == u64::MAX {
        0
    } else {
        diag::cpu_diag(active_cpu, 5)
    };

    let mut line = FixedBuffer::<2048>::new();
    let formatted = writeln!(
        line,
        concat!(
            "HVL1 C seq={} total={} cpuid={} msr={} msr_r={} msr_w={} last_msr=0x{:x} msr_action={} xsetbv={} ",
            "vmx={} pin=0x{:x} eptv={} eptm={} exc={} ",
            "hostfault={} gp={} nmi={} pf={} mc={} msrgp={} efer_r={} efer_w={} ",
            "aperf={} mperf={} dbg_r={} dbg_w={} lbr={} bughit={} bugcb={} freeze={} boot_stage={} ",
            "cmos_io_contention={} write_failures={} dropped_records={} active=0x{:x} active_count={} active_cpu={} ",
            "init={} sipi={} awaiting_sipi=0x{:x} init_stage={} init_stage_count={} init_last_cpu={} sipi_vector={} ",
            "exc_cpu={} exc_info=0x{:x} exc_error=0x{:x} idt_info=0x{:x} idt_error=0x{:x} ",
            "idt_events={} entry_conflict_info=0x{:x} entry_conflicts={} event_context_dropped={} ",
            "phase=0x{:x} leaf=0x{:x} command=0x{:x} cr_worker={} cr_phase=0x{:x} ",
            "cr_slot={} cr_req={} cr_done={} cr_status={} cr_kind={} cr_size={} ",
            "batch_state={} batch_processed={} batch_failures={} batch_processing={}"
        ),
        next_sequence(),
        diag::counter(0),
        diag::counter(1),
        diag::counter(9),
        diag::counter(14),
        diag::counter(15),
        diag::counter(12),
        diag::counter(13),
        diag::counter(7),
        diag::counter(22),
        diag::control(0),
        diag::counter(4),
        diag::counter(5),
        diag::counter(3),
        diag::control(30),
        diag::counter(10),
        diag::counter(11),
        diag::counter(19),
        diag::counter(20),
        diag::counter(16),
        diag::control(57),
        diag::control(58),
        diag::control(59),
        diag::control(60),
        diag::control(61),
        diag::control(62),
        diag::control(63),
        diag::control(52),
        diag::control(65),
        diag::control(130),
        diag::control(9),
        diag::ext_cmos_io_contention_count(),
        WRITE_FAILURES.load(Ordering::Relaxed),
        DROPPED_RECORDS.load(Ordering::Relaxed),
        active,
        active.count_ones(),
        active_cpu,
        diag::control(280),
        diag::control(281),
        diag::control(282),
        diag::control(283),
        diag::control(284),
        diag::control(285),
        diag::control(286),
        event.exception_cpu,
        event.exit_interruption_info,
        event.exit_interruption_error,
        event.idt_vectoring_info,
        event.idt_vectoring_error,
        event.idt_vectoring_event_count,
        event.entry_interruption_info,
        event.entry_event_conflict_count,
        event.dropped_updates,
        active_phase,
        active_leaf,
        active_command,
        client_read::debug_state(1),
        client_read::debug_state(17),
        client_read::debug_state(11),
        client_read::debug_state(2),
        client_read::debug_state(3),
        client_read::debug_state(4),
        client_read::debug_state(8),
        client_read::debug_state(6),
        client_read::debug_state(13),
        client_read::debug_state(15),
        client_read::debug_state(16),
        client_read::debug_state(18)
    )
    .is_ok();
    if !formatted || batch.write_str(line.as_str()).is_err() {
        DROPPED_RECORDS.fetch_add(1, Ordering::Relaxed);
    }
}

fn next_sequence() -> u64 {
    LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn open_log_file() -> Option<HANDLE> {
    open_output_file(LOG_PATH_UTF16)
}

fn open_output_file(path_utf16: &[u16]) -> Option<HANDLE> {
    let mut path = UNICODE_STRING {
        Length: ((path_utf16.len() - 1) * 2) as u16,
        MaximumLength: (path_utf16.len() * 2) as u16,
        Buffer: path_utf16.as_ptr() as *mut _,
    };
    let mut attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: &mut path,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let mut io_status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let mut handle: HANDLE = null_mut();
    let status = unsafe {
        ZwCreateFile(
            &mut handle,
            GENERIC_WRITE | SYNCHRONIZE,
            &mut attributes,
            &mut io_status,
            null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OVERWRITE_IF,
            // No FILE_WRITE_THROUGH: write-through + ZwFlushBuffersFile stacked
            // TLB shootdowns during bring-up (0x101). Explicit flush is gated.
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut(),
            0,
        )
    };
    (NT_SUCCESS(status) && !handle.is_null()).then_some(handle)
}

fn write_bytes(bytes: &[u8], flush: bool) -> bool {
    if bytes.is_empty() {
        return true;
    }
    // Skip entirely during VMX bring-up; see diag::LaunchIoQuiesceGuard.
    if !diag::diag_disk_io_enter() {
        return true;
    }

    let handle = LOG_HANDLE.load(Ordering::Acquire) as HANDLE;
    if handle.is_null() {
        diag::diag_disk_io_leave();
        WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    let success = write_handle_bytes(handle, bytes, flush);
    diag::diag_disk_io_leave();
    if !success {
        WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    success
}

fn write_handle_bytes(handle: HANDLE, bytes: &[u8], flush: bool) -> bool {
    if bytes.is_empty() {
        return true;
    }

    let mut write_status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let write_result = unsafe {
        ZwWriteFile(
            handle,
            null_mut(),
            None,
            null_mut(),
            &mut write_status,
            bytes.as_ptr() as PVOID,
            bytes.len() as u32,
            null_mut(),
            null_mut(),
        )
    };
    if !NT_SUCCESS(write_result) || write_status.Information != bytes.len() as u64 {
        return false;
    }

    if flush {
        let mut flush_status: IO_STATUS_BLOCK = unsafe { zeroed() };
        let flush_result = unsafe { ZwFlushBuffersFile(handle, &mut flush_status) };
        if !NT_SUCCESS(flush_result) {
            return false;
        }
        return true;
    }
    true
}

fn close_log_file() -> bool {
    let handle = LOG_HANDLE.swap(0, Ordering::AcqRel) as HANDLE;
    handle.is_null() || unsafe { NT_SUCCESS(ZwClose(handle)) }
}

fn delay_worker() {
    let mut interval = LARGE_INTEGER {
        QuadPart: WORKER_DELAY_100NS,
    };
    unsafe {
        let _ = KeDelayExecutionThread(_MODE::KernelMode as _, 0, &mut interval);
    }
}

struct FixedBuffer<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuffer<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn as_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(self.as_bytes()) }
    }
}

impl<const N: usize> Write for FixedBuffer<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = self.bytes.len().saturating_sub(self.len);
        if value.len() > remaining {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + value.len()].copy_from_slice(value.as_bytes());
        self.len += value.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn local_diag_build_flag_requires_exact_one() {
        assert!(enabled_by_build_flag(Some("1")));
        assert!(!enabled_by_build_flag(None));
        assert!(!enabled_by_build_flag(Some("0")));
        assert!(!enabled_by_build_flag(Some("true")));
    }

    #[test]
    fn kernel_log_path_matches_display_path() {
        let nt_path = String::from_utf16(&LOG_PATH_UTF16[..LOG_PATH_UTF16.len() - 1]).unwrap();
        assert_eq!(nt_path, r"\??\D:\cheat\hv_diag_live.log");
        assert_eq!(&nt_path[4..], LOG_PATH_DISPLAY);
    }

    #[test]
    fn cmos_capture_path_and_format_are_stable() {
        let nt_path =
            String::from_utf16(&CMOS_CAPTURE_PATH_UTF16[..CMOS_CAPTURE_PATH_UTF16.len() - 1])
                .unwrap();
        assert_eq!(nt_path, r"\??\D:\cheat\hv_cmos_capture.txt");
        assert_eq!(&nt_path[4..], CMOS_CAPTURE_PATH_DISPLAY);

        let mut raw = [0u8; terminal_capture::CMOS_BYTES];
        raw[0] = 0xab;
        raw[terminal_capture::CMOS_BYTES - 1] = 0x5a;
        let mut output = FixedBuffer::<512>::new();
        assert!(format_cmos_capture(&raw, &mut output));
        let text = output.as_str();
        let raw_line = text.lines().nth(1).unwrap();
        assert_eq!(raw_line.len(), "raw_hex=".len() + terminal_capture::CMOS_BYTES * 2);
        assert!(raw_line.starts_with("raw_hex=ab00"));
        assert!(raw_line.ends_with("005a"));
    }

    #[test]
    fn fixed_buffer_rejects_overflow() {
        let mut buffer = FixedBuffer::<4>::new();
        assert!(buffer.write_str("HVL1").is_ok());
        assert_eq!(buffer.as_bytes(), b"HVL1");
        assert!(buffer.write_str("x").is_err());
    }
}
