use {
    core::{
        ptr::null_mut,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    },
    wdk_sys::{
        _MM_COPY_ADDRESS__bindgen_ty_1,
        ntddk::{
            KeDelayExecutionThread, MmCopyMemory, PsCreateSystemThread, PsTerminateSystemThread,
            ZwClose,
        },
        _MODE, HANDLE, LARGE_INTEGER, MM_COPY_ADDRESS, MM_COPY_MEMORY_PHYSICAL, NT_SUCCESS,
        PHYSICAL_ADDRESS, PVOID, STATUS_SUCCESS, THREAD_ALL_ACCESS,
    },
};

pub const READ_PENDING: u64 = u64::MAX - 3;

const STATUS_OK: u64 = 0;
const STATUS_FAILED: u64 = 1;
const STATUS_TRUE: u64 = 1;
const STATUS_FALSE: u64 = 0;
const MAX_READ_SIZE: usize = 0x1000;
const ARMED_IDLE_DELAY_100NS: i64 = -100;
const UNARMED_IDLE_DELAY_100NS: i64 = -100_000;
const SLOT_IDLE: u64 = 0;
const SLOT_SUBMITTING: u64 = 1;
const SLOT_PENDING: u64 = 2;
const SLOT_READY: u64 = 3;

static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);
static DONE_SEQ: AtomicU64 = AtomicU64::new(0);
static SLOT_STATE: AtomicU64 = AtomicU64::new(SLOT_IDLE);
static REQUEST_KIND: AtomicU64 = AtomicU64::new(REQUEST_KIND_PHYSICAL);
static REQUEST_PA: AtomicU64 = AtomicU64::new(0);
static REQUEST_CR3: AtomicU64 = AtomicU64::new(0);
static REQUEST_VA: AtomicU64 = AtomicU64::new(0);
static REQUEST_SIZE: AtomicU64 = AtomicU64::new(0);
static RESULT_VALUE: AtomicU64 = AtomicU64::new(0);
static RESULT_SIZE: AtomicU64 = AtomicU64::new(0);
static RESULT_STATUS: AtomicU64 = AtomicU64::new(STATUS_FAILED);
static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static WORKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static mut RESULT_BYTES: [u8; MAX_READ_SIZE] = [0; MAX_READ_SIZE];

const REQUEST_KIND_PHYSICAL: u64 = 0;
const REQUEST_KIND_VIRTUAL: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalReadRequest {
    pub seq: u64,
    pub kind: ReadRequestKind,
    pub pa: u64,
    pub cr3: u64,
    pub va: u64,
    pub size: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadRequestKind {
    Physical,
    Virtual,
}

pub fn mark_worker_started(started: bool) {
    WORKER_STARTED.store(started, Ordering::Release);
}

pub fn worker_started() -> bool {
    WORKER_STARTED.load(Ordering::Acquire)
}

const fn worker_enabled_by_build_flag(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 1 && bytes[0] == b'1'
}

pub fn worker_enabled_by_build() -> bool {
    worker_enabled_by_build_flag(option_env!("HV_USER_CLIENT_READS"))
}

pub fn submit_physical_read(pa: u64, size: usize) -> u64 {
    submit_read_request(ReadRequestKind::Physical, pa, 0, 0, size)
}

pub fn submit_virtual_read(cr3: u64, va: u64, size: usize) -> u64 {
    if cr3 == 0 {
        return 0;
    }
    submit_read_request(ReadRequestKind::Virtual, 0, cr3, va, size)
}

fn submit_read_request(kind: ReadRequestKind, pa: u64, cr3: u64, va: u64, size: usize) -> u64 {
    if !worker_started() || !(1..=MAX_READ_SIZE).contains(&size) {
        return 0;
    }

    if SLOT_STATE
        .compare_exchange(
            SLOT_IDLE,
            SLOT_SUBMITTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return 0;
    }

    let current = REQUEST_SEQ.load(Ordering::Acquire);
    let mut next = current.wrapping_add(1);
    if next == 0 {
        next = 1;
    }

    REQUEST_KIND.store(request_kind_value(kind), Ordering::Relaxed);
    REQUEST_PA.store(pa, Ordering::Relaxed);
    REQUEST_CR3.store(cr3, Ordering::Relaxed);
    REQUEST_VA.store(va, Ordering::Relaxed);
    REQUEST_SIZE.store(size as u64, Ordering::Relaxed);
    RESULT_VALUE.store(0, Ordering::Relaxed);
    RESULT_SIZE.store(0, Ordering::Relaxed);
    RESULT_STATUS.store(STATUS_FAILED, Ordering::Relaxed);
    REQUEST_SEQ.store(next, Ordering::Release);
    SLOT_STATE.store(SLOT_PENDING, Ordering::Release);
    next
}

fn request_kind_value(kind: ReadRequestKind) -> u64 {
    match kind {
        ReadRequestKind::Physical => REQUEST_KIND_PHYSICAL,
        ReadRequestKind::Virtual => REQUEST_KIND_VIRTUAL,
    }
}

fn request_kind_from_value(value: u64) -> Option<ReadRequestKind> {
    match value {
        REQUEST_KIND_PHYSICAL => Some(ReadRequestKind::Physical),
        REQUEST_KIND_VIRTUAL => Some(ReadRequestKind::Virtual),
        _ => None,
    }
}

pub fn pending_request() -> Option<PhysicalReadRequest> {
    if SLOT_STATE.load(Ordering::Acquire) != SLOT_PENDING {
        return None;
    }

    let seq = REQUEST_SEQ.load(Ordering::Acquire);
    if seq == 0 {
        return None;
    }

    Some(PhysicalReadRequest {
        seq,
        kind: request_kind_from_value(REQUEST_KIND.load(Ordering::Relaxed))?,
        pa: REQUEST_PA.load(Ordering::Relaxed),
        cr3: REQUEST_CR3.load(Ordering::Relaxed),
        va: REQUEST_VA.load(Ordering::Relaxed),
        size: REQUEST_SIZE.load(Ordering::Relaxed) as usize,
    })
}

pub fn complete_physical_read(seq: u64, value: u64, ok: bool) {
    let bytes = value.to_le_bytes();
    let size = (REQUEST_SIZE.load(Ordering::Acquire) as usize).min(8);
    if ok && size > 0 {
        write_result_bytes(0, &bytes[..size]);
    }
    complete_read(seq, size, ok);
}

fn complete_read(seq: u64, size: usize, ok: bool) {
    if SLOT_STATE.load(Ordering::Acquire) != SLOT_PENDING
        || REQUEST_SEQ.load(Ordering::Acquire) != seq
    {
        return;
    }

    let value = if ok { read_result_word_unchecked(0) } else { 0 };
    RESULT_VALUE.store(value, Ordering::Relaxed);
    RESULT_SIZE.store(if ok { size as u64 } else { 0 }, Ordering::Relaxed);
    RESULT_STATUS.store(
        if ok { STATUS_OK } else { STATUS_FAILED },
        Ordering::Relaxed,
    );
    DONE_SEQ.store(seq, Ordering::Release);
    SLOT_STATE.store(SLOT_READY, Ordering::Release);
}

pub fn poll_physical_read(seq: u64) -> u64 {
    if REQUEST_SEQ.load(Ordering::Acquire) != seq {
        return 0;
    }

    match SLOT_STATE.load(Ordering::Acquire) {
        SLOT_SUBMITTING | SLOT_PENDING => return READ_PENDING,
        SLOT_READY => {}
        _ => return 0,
    }

    if DONE_SEQ.load(Ordering::Acquire) != seq {
        return READ_PENDING;
    }

    let result = if RESULT_STATUS.load(Ordering::Relaxed) == STATUS_OK {
        read_result_word(seq, 0)
    } else {
        0
    };
    SLOT_STATE.store(SLOT_IDLE, Ordering::Release);
    result
}

pub fn poll_read_info(seq: u64) -> u64 {
    if REQUEST_SEQ.load(Ordering::Acquire) != seq {
        return 0;
    }

    match SLOT_STATE.load(Ordering::Acquire) {
        SLOT_SUBMITTING | SLOT_PENDING => return READ_PENDING,
        SLOT_READY => {}
        _ => return 0,
    }

    if DONE_SEQ.load(Ordering::Acquire) != seq {
        return READ_PENDING;
    }

    if RESULT_STATUS.load(Ordering::Relaxed) == STATUS_OK {
        RESULT_SIZE.load(Ordering::Relaxed)
    } else {
        0
    }
}

pub fn read_result_word(seq: u64, offset: u64) -> u64 {
    if REQUEST_SEQ.load(Ordering::Acquire) != seq
        || DONE_SEQ.load(Ordering::Acquire) != seq
        || SLOT_STATE.load(Ordering::Acquire) != SLOT_READY
        || RESULT_STATUS.load(Ordering::Relaxed) != STATUS_OK
    {
        return 0;
    }

    let size = RESULT_SIZE.load(Ordering::Acquire) as usize;
    let offset = offset as usize;
    if offset >= size || offset >= MAX_READ_SIZE {
        return 0;
    }

    read_result_word_unchecked(offset)
}

pub fn release_read_result(seq: u64) -> u64 {
    if REQUEST_SEQ.load(Ordering::Acquire) != seq || DONE_SEQ.load(Ordering::Acquire) != seq {
        return STATUS_FAILED;
    }
    if SLOT_STATE.load(Ordering::Acquire) != SLOT_READY {
        return STATUS_FAILED;
    }

    SLOT_STATE.store(SLOT_IDLE, Ordering::Release);
    STATUS_OK
}

pub fn reclaim_completed_result_for_new_client() -> bool {
    let seq = REQUEST_SEQ.load(Ordering::Acquire);
    if seq == 0 || DONE_SEQ.load(Ordering::Acquire) != seq {
        return false;
    }

    SLOT_STATE
        .compare_exchange(SLOT_READY, SLOT_IDLE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub fn debug_state(id: u64) -> u64 {
    match id {
        0 => {
            if worker_enabled_by_build() {
                STATUS_TRUE
            } else {
                STATUS_FALSE
            }
        }
        1 => {
            if worker_started() {
                STATUS_TRUE
            } else {
                STATUS_FALSE
            }
        }
        2 => REQUEST_SEQ.load(Ordering::Acquire),
        3 => DONE_SEQ.load(Ordering::Acquire),
        4 => RESULT_STATUS.load(Ordering::Acquire),
        5 => REQUEST_PA.load(Ordering::Acquire),
        6 => REQUEST_SIZE.load(Ordering::Acquire),
        7 => {
            if WORKER_SHUTDOWN.load(Ordering::Acquire) {
                STATUS_TRUE
            } else {
                STATUS_FALSE
            }
        }
        8 => REQUEST_KIND.load(Ordering::Acquire),
        9 => REQUEST_CR3.load(Ordering::Acquire),
        10 => REQUEST_VA.load(Ordering::Acquire),
        11 => SLOT_STATE.load(Ordering::Acquire),
        12 => RESULT_SIZE.load(Ordering::Acquire),
        _ => u64::MAX,
    }
}

pub fn start_worker_if_enabled() -> bool {
    if !worker_enabled_by_build() {
        return true;
    }
    if worker_started() {
        return true;
    }

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
        mark_worker_started(false);
        return false;
    }

    mark_worker_started(true);
    if !handle.is_null() {
        unsafe {
            let _ = ZwClose(handle);
        }
    }
    true
}

pub fn stop_worker() {
    WORKER_SHUTDOWN.store(true, Ordering::Release);
    mark_worker_started(false);
}

unsafe extern "C" fn worker_main(_start_context: PVOID) {
    let mut idle_spins = 0u32;
    while !WORKER_SHUTDOWN.load(Ordering::Acquire) {
        if !crate::intel::diag::client_reads_armed() {
            delay_worker(false);
            idle_spins = 0;
            continue;
        }

        if let Some(request) = pending_request() {
            let result = match request.kind {
                ReadRequestKind::Physical => read_phys_into_result(request.pa, request.size),
                ReadRequestKind::Virtual => {
                    read_virtual_into_result(request.cr3, request.va, request.size)
                }
            };
            match result {
                Some(size) => complete_read(request.seq, size, true),
                None => complete_read(request.seq, 0, false),
            }
            idle_spins = 0;
            continue;
        }

        idle_spins = idle_spins.wrapping_add(1);
        if idle_spins < 100_000 {
            core::hint::spin_loop();
        } else {
            delay_worker(true);
            idle_spins = 0;
        }
    }

    let _ = PsTerminateSystemThread(STATUS_SUCCESS);
}

fn idle_delay_100ns(client_reads_armed: bool) -> i64 {
    if client_reads_armed {
        ARMED_IDLE_DELAY_100NS
    } else {
        UNARMED_IDLE_DELAY_100NS
    }
}

fn delay_worker(client_reads_armed: bool) {
    let mut interval = LARGE_INTEGER {
        QuadPart: idle_delay_100ns(client_reads_armed),
    };
    unsafe {
        let _ = KeDelayExecutionThread(_MODE::KernelMode as _, 0, &mut interval);
    }
}

fn physical_copy_address(pa: u64) -> MM_COPY_ADDRESS {
    MM_COPY_ADDRESS {
        __bindgen_anon_1: _MM_COPY_ADDRESS__bindgen_ty_1 {
            PhysicalAddress: PHYSICAL_ADDRESS {
                QuadPart: pa as i64,
            },
        },
    }
}

fn read_phys_sized(pa: u64, size: usize) -> Option<u64> {
    if !(1..=8).contains(&size) {
        return None;
    }

    let mut buffer = [0u8; 8];
    let mut bytes_transferred = 0u64;
    let status = unsafe {
        MmCopyMemory(
            buffer.as_mut_ptr().cast(),
            physical_copy_address(pa),
            size as u64,
            MM_COPY_MEMORY_PHYSICAL,
            &mut bytes_transferred,
        )
    };

    (NT_SUCCESS(status) && bytes_transferred == size as u64).then(|| u64::from_le_bytes(buffer))
}

fn result_bytes_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(RESULT_BYTES).cast::<u8>()
}

fn read_result_word_unchecked(offset: usize) -> u64 {
    let size = RESULT_SIZE.load(Ordering::Acquire) as usize;
    let mut bytes = [0u8; 8];
    let available = size.saturating_sub(offset).min(8);
    if available == 0 {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            result_bytes_ptr().add(offset),
            bytes.as_mut_ptr(),
            available,
        );
    }
    u64::from_le_bytes(bytes)
}

fn write_result_bytes(offset: usize, bytes: &[u8]) {
    if offset >= MAX_READ_SIZE {
        return;
    }
    let len = bytes.len().min(MAX_READ_SIZE - offset);
    if len == 0 {
        return;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), result_bytes_ptr().add(offset), len);
    }
}

fn read_phys_to_ptr(pa: u64, dst: *mut u8, size: usize) -> Option<usize> {
    if !(1..=MAX_READ_SIZE).contains(&size) {
        return None;
    }

    let mut bytes_transferred = 0u64;
    let status = unsafe {
        MmCopyMemory(
            dst.cast(),
            physical_copy_address(pa),
            size as u64,
            MM_COPY_MEMORY_PHYSICAL,
            &mut bytes_transferred,
        )
    };

    (NT_SUCCESS(status) && bytes_transferred == size as u64).then_some(size)
}

fn read_phys_into_result(pa: u64, size: usize) -> Option<usize> {
    read_phys_to_ptr(pa, result_bytes_ptr(), size)
}

fn read_virtual_into_result(cr3: u64, va: u64, size: usize) -> Option<usize> {
    if cr3 == 0 || !(1..=MAX_READ_SIZE).contains(&size) {
        return None;
    }

    let mut copied = 0usize;
    while copied < size {
        let cur_va = va.wrapping_add(copied as u64);
        let page_left = 0x1000usize - (cur_va as usize & 0xFFF);
        let chunk = (size - copied).min(page_left);
        let pa = translate_va_to_pa(cr3, cur_va)?;
        let dst = unsafe { result_bytes_ptr().add(copied) };
        read_phys_to_ptr(pa, dst, chunk)?;
        copied += chunk;
    }

    Some(copied)
}

fn read_page_table_entry(pa: u64) -> Option<u64> {
    read_phys_sized(pa, 8)
}

fn translate_va_to_pa(cr3: u64, va: u64) -> Option<u64> {
    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;
    let offset = va & 0xFFF;

    let pml4e = read_page_table_entry(pml4_base + pml4_idx * 8)?;
    if pml4e & 1 == 0 {
        return None;
    }

    let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
    let pdpte = read_page_table_entry(pdpt_base + pdpt_idx * 8)?;
    if pdpte & 1 == 0 {
        return None;
    }
    if pdpte & 0x80 != 0 {
        return Some((pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF));
    }

    let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
    let pde = read_page_table_entry(pd_base + pd_idx * 8)?;
    if pde & 1 == 0 {
        return None;
    }
    if pde & 0x80 != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }

    let pt_base = pde & 0x000F_FFFF_FFFF_F000;
    let pte = read_page_table_entry(pt_base + pt_idx * 8)?;
    if pte & 1 == 0 {
        return None;
    }

    Some((pte & 0x000F_FFFF_FFFF_F000) | offset)
}

#[cfg(test)]
pub fn reset_for_test() {
    REQUEST_SEQ.store(0, Ordering::Relaxed);
    DONE_SEQ.store(0, Ordering::Relaxed);
    SLOT_STATE.store(SLOT_IDLE, Ordering::Relaxed);
    REQUEST_KIND.store(REQUEST_KIND_PHYSICAL, Ordering::Relaxed);
    REQUEST_PA.store(0, Ordering::Relaxed);
    REQUEST_CR3.store(0, Ordering::Relaxed);
    REQUEST_VA.store(0, Ordering::Relaxed);
    REQUEST_SIZE.store(0, Ordering::Relaxed);
    RESULT_VALUE.store(0, Ordering::Relaxed);
    RESULT_SIZE.store(0, Ordering::Relaxed);
    RESULT_STATUS.store(STATUS_FAILED, Ordering::Relaxed);
    WORKER_SHUTDOWN.store(false, Ordering::Relaxed);
    mark_worker_started(true);
}

#[cfg(test)]
static TEST_LOCK: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub struct TestLockGuard;

#[cfg(test)]
pub fn test_lock() -> TestLockGuard {
    while TEST_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    TestLockGuard
}

#[cfg(test)]
impl Drop for TestLockGuard {
    fn drop(&mut self) {
        TEST_LOCK.store(false, Ordering::Release);
    }
}

#[cfg(test)]
pub fn complete_for_test(seq: u64, value: u64, ok: bool) {
    complete_physical_read(seq, value, ok);
}

#[cfg(test)]
pub fn complete_bytes_for_test(seq: u64, bytes: &[u8], ok: bool) {
    let size = bytes.len().min(MAX_READ_SIZE);
    if ok {
        write_result_bytes(0, &bytes[..size]);
    }
    complete_read(seq, size, ok);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_uses_long_idle_delay_until_client_reads_are_armed() {
        let _guard = test_lock();

        assert!(idle_delay_100ns(false) < idle_delay_100ns(true));
        assert_eq!(idle_delay_100ns(false), -100_000);
    }

    #[test]
    fn debug_state_reports_request_progress() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_physical_read(0x1234, 8);
        assert_eq!(debug_state(1), 1);
        assert_eq!(debug_state(2), seq);
        assert_eq!(debug_state(3), 0);
        assert_eq!(debug_state(5), 0x1234);
        assert_eq!(debug_state(6), 8);

        complete_physical_read(seq, 0x55, true);
        assert_eq!(debug_state(3), seq);
        assert_eq!(debug_state(4), STATUS_OK);
    }

    #[test]
    fn virtual_read_request_carries_address_space_and_va() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 8);
        let request = pending_request().expect("pending virtual read request");

        assert_eq!(request.seq, seq);
        assert_eq!(request.cr3, 0x1234_5000);
        assert_eq!(request.va, 0x7ff6_1234_5678);
        assert_eq!(request.size, 8);
    }

    #[test]
    fn completed_result_cannot_be_overwritten_before_poll() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 8);
        assert_ne!(seq, 0);

        assert_eq!(submit_virtual_read(0x1234_5000, 0x7ff6_1234_5680, 8), 0);

        complete_physical_read(seq, 0x1122_3344_5566_7788, true);

        assert_eq!(submit_virtual_read(0x1234_5000, 0x7ff6_1234_5680, 8), 0);
        assert_eq!(poll_physical_read(seq), 0x1122_3344_5566_7788);

        let next = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5680, 8);
        assert_ne!(next, 0);
        assert_ne!(next, seq);
    }

    #[test]
    fn bulk_virtual_read_request_allows_page_sized_payload() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5000, 0x1000);

        assert_ne!(seq, 0);
        let request = pending_request().expect("pending bulk virtual read request");
        assert_eq!(request.size, 0x1000);
    }

    #[test]
    fn bulk_result_words_do_not_release_slot_until_explicit_release() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 16);
        assert_ne!(seq, 0);

        complete_bytes_for_test(
            seq,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            true,
        );

        assert_eq!(poll_read_info(seq), 16);
        assert_eq!(read_result_word(seq, 0), 0x0807_0605_0403_0201);
        assert_eq!(read_result_word(seq, 8), 0x100f_0e0d_0c0b_0a09);
        assert_eq!(submit_virtual_read(0x1234_5000, 0x7ff6_1234_5688, 8), 0);
        assert_eq!(release_read_result(seq), 0);

        let next = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5688, 8);
        assert_ne!(next, 0);
        assert_ne!(next, seq);
    }

    #[test]
    fn arm_reclaims_completed_result_left_by_dead_client() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 16);
        assert_ne!(seq, 0);
        complete_bytes_for_test(seq, &[1, 2, 3, 4], true);

        assert_eq!(debug_state(11), SLOT_READY);
        crate::intel::diag::arm_client_reads();

        let next = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5688, 8);
        assert_ne!(next, 0);
        assert_ne!(next, seq);
    }
}
