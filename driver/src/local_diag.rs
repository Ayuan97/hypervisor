use {
    core::{
        fmt::{self, Write},
        mem::{size_of, zeroed},
        ptr::null_mut,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    },
    hypervisor::intel::diag,
    wdk_sys::{
        ntddk::{
            KeDelayExecutionThread, PsCreateSystemThread, PsTerminateSystemThread, ZwClose,
            ZwCreateFile, ZwFlushBuffersFile, ZwWaitForSingleObject, ZwWriteFile,
        },
        FILE_ATTRIBUTE_NORMAL, FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, GENERIC_WRITE, HANDLE,
        IO_STATUS_BLOCK, LARGE_INTEGER, NT_SUCCESS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE,
        OBJ_KERNEL_HANDLE, PVOID, STATUS_SUCCESS, SYNCHRONIZE, THREAD_ALL_ACCESS, UNICODE_STRING,
        _MODE,
    },
};

const WORKER_DELAY_100NS: i64 = -1_000_000; // 100 ms
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

static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static WORKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static WORKER_HANDLE: AtomicU64 = AtomicU64::new(0);
static LOG_HANDLE: AtomicU64 = AtomicU64::new(0);
static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static WRITE_FAILURES: AtomicU64 = AtomicU64::new(0);
static DROPPED_RECORDS: AtomicU64 = AtomicU64::new(0);

const fn enabled_by_build_flag(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 1 && bytes[0] == b'1'
}

pub fn enabled_by_build() -> bool {
    enabled_by_build_flag(option_env!("HV_LOCAL_DIAG"))
}

pub fn start_worker_if_enabled() -> bool {
    if !enabled_by_build() || WORKER_STARTED.load(Ordering::Acquire) {
        return true;
    }

    let Some(log_handle) = open_log_file() else {
        return false;
    };
    LOG_HANDLE.store(log_handle as u64, Ordering::Release);
    WORKER_SHUTDOWN.store(false, Ordering::Release);
    if !write_start_record() {
        close_log_file();
        return false;
    }

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

unsafe extern "C" fn worker_main(_context: PVOID) {
    let mut next_ring_index = [0u64; diag::MAX_TRACKED_CPUS];
    for (cpu, next) in next_ring_index.iter_mut().enumerate() {
        let current = diag::per_cpu_ring_idx(cpu as u64);
        *next = current.saturating_sub(1);
    }

    let mut next_cpu = 0usize;
    let mut tick = 0u64;
    while !WORKER_SHUTDOWN.load(Ordering::Acquire) {
        let mut batch = FixedBuffer::<4096>::new();
        next_cpu = append_ring_updates(&mut batch, &mut next_ring_index, next_cpu);
        if tick % 10 == 0 {
            append_counter_snapshot(&mut batch);
        }
        if !batch.as_bytes().is_empty() {
            write_and_flush(batch.as_bytes());
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
    write_and_flush(stop.as_bytes());
    WORKER_STARTED.store(false, Ordering::Release);
    let _ = PsTerminateSystemThread(STATUS_SUCCESS);
}

fn write_start_record() -> bool {
    let mut start = FixedBuffer::<512>::new();
    let formatted = writeln!(
        start,
        "HVL1 START seq={} path={} cpus={} ring_size={} period_ms=100 boot_stage={}",
        next_sequence(),
        LOG_PATH_DISPLAY,
        diag::MAX_TRACKED_CPUS,
        diag::PER_CPU_RING_SIZE,
        diag::control(9)
    )
    .is_ok();
    formatted && write_and_flush(start.as_bytes())
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
    let mut line = FixedBuffer::<512>::new();
    let formatted = writeln!(
        line,
        concat!(
            "HVL1 C seq={} total={} cpuid={} msr={} vmx={} eptv={} eptm={} exc={} ",
            "hostfault={} gp={} nmi={} pf={} mc={} msrgp={} efer_r={} efer_w={} ",
            "aperf={} mperf={} dbg_r={} dbg_w={} lbr={} bughit={} bugcb={} freeze={} boot_stage={} ",
            "write_failures={} dropped_records={}"
        ),
        next_sequence(),
        diag::counter(0),
        diag::counter(1),
        diag::counter(9),
        diag::counter(22),
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
        WRITE_FAILURES.load(Ordering::Relaxed),
        DROPPED_RECORDS.load(Ordering::Relaxed)
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
    let mut path = UNICODE_STRING {
        Length: ((LOG_PATH_UTF16.len() - 1) * 2) as u16,
        MaximumLength: (LOG_PATH_UTF16.len() * 2) as u16,
        Buffer: LOG_PATH_UTF16.as_ptr() as *mut _,
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
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
            null_mut(),
            0,
        )
    };
    (NT_SUCCESS(status) && !handle.is_null()).then_some(handle)
}

fn write_and_flush(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let handle = LOG_HANDLE.load(Ordering::Acquire) as HANDLE;
    if handle.is_null() {
        WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
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
        WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    let mut flush_status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let flush_result = unsafe { ZwFlushBuffersFile(handle, &mut flush_status) };
    if !NT_SUCCESS(flush_result) {
        WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
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
    fn fixed_buffer_rejects_overflow() {
        let mut buffer = FixedBuffer::<4>::new();
        assert!(buffer.write_str("HVL1").is_ok());
        assert_eq!(buffer.as_bytes(), b"HVL1");
        assert!(buffer.write_str("x").is_err());
    }
}
