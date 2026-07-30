use {
    core::{
        arch::asm,
        fmt::{self, Write},
        hint::spin_loop,
        ptr::null_mut,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    },
    hypervisor::intel::diag,
    wdk_sys::{
        ntddk::{
            KeDelayExecutionThread, PsCreateSystemThread, PsTerminateSystemThread, ZwClose,
            ZwWaitForSingleObject,
        },
        _MODE, HANDLE, LARGE_INTEGER, NT_SUCCESS, PVOID, STATUS_SUCCESS, THREAD_ALL_ACCESS,
    },
};

const COM2_DATA: u16 = 0x2f8;
const COM2_INTERRUPT_ENABLE: u16 = 0x2f9;
const COM2_FIFO_CONTROL: u16 = 0x2fa;
const COM2_LINE_CONTROL: u16 = 0x2fb;
const COM2_MODEM_CONTROL: u16 = 0x2fc;
const COM2_LSR: u16 = 0x2fd;
const UART_TX_READY: u8 = 0x20;
const UART_POLL_LIMIT: usize = 100_000;
const WORKER_DELAY_100NS: i64 = -1_000_000; // 100 ms
const CPU_RECORDS_PER_TICK: usize = 4;

static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static WORKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static WORKER_HANDLE: AtomicU64 = AtomicU64::new(0);
static SERIAL_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static SERIAL_DROPPED_LINES: AtomicU64 = AtomicU64::new(0);

const fn enabled_by_build_flag(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 1 && bytes[0] == b'1'
}

pub fn enabled_by_build() -> bool {
    enabled_by_build_flag(option_env!("HV_SERIAL_DIAG"))
}

pub fn start_worker_if_enabled() -> bool {
    if !enabled_by_build() || WORKER_STARTED.load(Ordering::Acquire) {
        return true;
    }

    uart_init_115200();
    WORKER_SHUTDOWN.store(false, Ordering::Release);
    let mut handle: HANDLE = null_mut();
    let status = unsafe {
        PsCreateSystemThread(
            &mut handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            null_mut(),
            Some(worker_main),
            null_mut(),
        )
    };
    if !NT_SUCCESS(status) {
        return false;
    }

    WORKER_HANDLE.store(handle as u64, Ordering::Release);
    WORKER_STARTED.store(true, Ordering::Release);
    true
}

pub fn stop_worker() -> bool {
    WORKER_SHUTDOWN.store(true, Ordering::Release);
    let handle = WORKER_HANDLE.load(Ordering::Acquire) as HANDLE;
    if handle.is_null() {
        WORKER_STARTED.store(false, Ordering::Release);
        return true;
    }

    unsafe {
        let wait_status = ZwWaitForSingleObject(handle, false as _, null_mut());
        if !NT_SUCCESS(wait_status) {
            return false;
        }
        if !NT_SUCCESS(ZwClose(handle)) {
            return false;
        }
    }
    WORKER_HANDLE.store(0, Ordering::Release);
    WORKER_STARTED.store(false, Ordering::Release);
    true
}

unsafe extern "C" fn worker_main(_context: PVOID) {
    let mut next_ring_index = [0u64; diag::MAX_TRACKED_CPUS];
    for (cpu, next) in next_ring_index.iter_mut().enumerate() {
        let current = diag::per_cpu_ring_idx(cpu as u64);
        *next = current.saturating_sub(1);
    }

    emit_start();
    let mut next_cpu = 0usize;
    let mut tick = 0u64;
    while !WORKER_SHUTDOWN.load(Ordering::Acquire) {
        next_cpu = emit_ring_updates(&mut next_ring_index, next_cpu);
        if tick % 10 == 0 {
            emit_counter_snapshot();
        }
        tick = tick.wrapping_add(1);
        delay_worker();
    }
    emit_stop();
    WORKER_STARTED.store(false, Ordering::Release);
    let _ = PsTerminateSystemThread(STATUS_SUCCESS);
}

fn emit_ring_updates(
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
                let serial_sequence = SERIAL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let mut line = LineBuffer::new();
                let _ = writeln!(
                    line,
                    concat!(
                        "HVS1 R seq={} cpu={} ring_seq={} overwritten={} ",
                        "reason=0x{:x} rip=0x{:x} qual=0x{:x} rax=0x{:x}\r"
                    ),
                    serial_sequence,
                    cpu,
                    entry.sequence,
                    overwritten,
                    entry.reason,
                    entry.rip,
                    entry.qualification,
                    entry.rax
                );
                emit_line(line.as_bytes());
                next_ring_index[cpu] = current;
                emitted += 1;
            }
        }
        cpu = (cpu + 1) % diag::MAX_TRACKED_CPUS;
        scanned += 1;
    }
    cpu
}

fn emit_start() {
    let serial_sequence = SERIAL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "HVS1 START seq={} cpus={} ring_size={} period_ms=100\r",
        serial_sequence,
        diag::MAX_TRACKED_CPUS,
        diag::PER_CPU_RING_SIZE
    );
    emit_line(line.as_bytes());
}

fn emit_stop() {
    let serial_sequence = SERIAL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        "HVS1 STOP seq={} dropped_lines={}\r",
        serial_sequence,
        SERIAL_DROPPED_LINES.load(Ordering::Relaxed)
    );
    emit_line(line.as_bytes());
}

fn emit_counter_snapshot() {
    let serial_sequence = SERIAL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut line = LineBuffer::new();
    let _ = writeln!(
        line,
        concat!(
            "HVS1 C seq={} total={} cpuid={} msr={} vmx={} eptv={} eptm={} exc={} ",
            "hostfault={} gp={} nmi={} pf={} mc={} msrgp={} efer_r={} efer_w={} ",
            "aperf={} mperf={} dbg_r={} dbg_w={} lbr={} bughit={} bugcb={} freeze={} dropped={}\r"
        ),
        serial_sequence,
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
        SERIAL_DROPPED_LINES.load(Ordering::Relaxed)
    );
    emit_line(line.as_bytes());
}

fn emit_line(bytes: &[u8]) {
    for &byte in bytes {
        if !uart_put_byte(byte) {
            SERIAL_DROPPED_LINES.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
}

fn uart_put_byte(byte: u8) -> bool {
    for _ in 0..UART_POLL_LIMIT {
        let status: u8;
        unsafe {
            asm!(
                "in al, dx",
                out("al") status,
                in("dx") COM2_LSR,
                options(nomem, nostack, preserves_flags)
            );
        }
        if status == u8::MAX {
            return false;
        }
        if status & UART_TX_READY != 0 {
            unsafe {
                asm!(
                    "out dx, al",
                    in("dx") COM2_DATA,
                    in("al") byte,
                    options(nomem, nostack, preserves_flags)
                );
            }
            return true;
        }
        spin_loop();
    }
    false
}

fn uart_init_115200() {
    unsafe {
        uart_out(COM2_INTERRUPT_ENABLE, 0);
        uart_out(COM2_LINE_CONTROL, 0x80);
        uart_out(COM2_DATA, 1);
        uart_out(COM2_INTERRUPT_ENABLE, 0);
        uart_out(COM2_LINE_CONTROL, 3);
        uart_out(COM2_FIFO_CONTROL, 0xc7);
        uart_out(COM2_MODEM_CONTROL, 0x0b);
    }
}

unsafe fn uart_out(port: u16, value: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

fn delay_worker() {
    let mut interval = LARGE_INTEGER {
        QuadPart: WORKER_DELAY_100NS,
    };
    unsafe {
        let _ = KeDelayExecutionThread(_MODE::KernelMode as _, 0, &mut interval);
    }
}

struct LineBuffer {
    bytes: [u8; 512],
    len: usize,
}

impl LineBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Write for LineBuffer {
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

    #[test]
    fn serial_diag_build_flag_requires_exact_one() {
        assert!(enabled_by_build_flag(Some("1")));
        assert!(!enabled_by_build_flag(None));
        assert!(!enabled_by_build_flag(Some("0")));
        assert!(!enabled_by_build_flag(Some("true")));
    }

    #[test]
    fn line_buffer_rejects_overflow() {
        let mut line = LineBuffer::new();
        assert!(line.write_str("HVS1").is_ok());
        assert_eq!(line.as_bytes(), b"HVS1");
        assert!(line
            .write_str(core::str::from_utf8(&[b'x'; 512]).unwrap())
            .is_err());
    }
}
