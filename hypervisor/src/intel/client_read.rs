use {
    crate::utils::capture::M128A,
    core::{
        ptr::null_mut,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    },
    wdk_sys::{
        _MM_COPY_ADDRESS__bindgen_ty_1,
        ntddk::{
            IoAllocateMdl, IoFreeMdl, KeDelayExecutionThread, KeStackAttachProcess,
            KeUnstackDetachProcess, MmCopyMemory, MmMapIoSpaceEx, MmMapLockedPagesSpecifyCache,
            MmUnlockPages, MmUnmapIoSpace, MmUnmapLockedPages, ObDereferenceObjectDeferDelete,
            PsCreateSystemThread, PsGetCurrentProcessId, PsLookupProcessByProcessId,
            PsTerminateSystemThread, ZwClose, ZwWaitForSingleObject,
        },
        MdlMappingNoExecute, _KAPC_STATE, _MEMORY_CACHING_TYPE, _MM_PAGE_PRIORITY, _MODE, HANDLE,
        LARGE_INTEGER, MM_COPY_ADDRESS, MM_COPY_MEMORY_PHYSICAL, NT_SUCCESS, PAGE_READWRITE,
        PEPROCESS, PHYSICAL_ADDRESS, PMDL, PRKPROCESS, PVOID, STATUS_SUCCESS, THREAD_ALL_ACCESS,
    },
};

#[cfg(not(test))]
use wdk_sys::_LOCK_OPERATION;

pub const READ_PENDING: u64 = u64::MAX - 3;

const STATUS_OK: u64 = 0;
const STATUS_FAILED: u64 = 1;
const STATUS_TRUE: u64 = 1;
const STATUS_FALSE: u64 = 0;
const MAX_READ_SIZE: usize = 0x1000;
const XMM_RESULT_REGS: usize = 16;
const XMM_RESULT_BYTES: usize = XMM_RESULT_REGS * 16;
const USER_VA_LIMIT: u64 = 0x0000_8000_0000_0000;
pub const BATCH_BUFFER_BYTES: usize = 0x1_0000;
pub const BATCH_BUFFER_MAX_BYTES: usize = BATCH_BUFFER_BYTES;
const BATCH_HEADER_BYTES: usize = 64;
const BATCH_REQUEST_BYTES: usize = 32;
const BATCH_DATA_OFFSET: usize = 0x2000;
const BATCH_MAX_REQUESTS: usize = 128;
const BATCH_MAGIC: u32 = 0x3142_5648;
const BATCH_VERSION: u32 = 1;
const BATCH_STATE_SUBMITTED: u32 = 1;
pub const BATCH_STATE_DONE: u32 = 2;
pub const BATCH_KIND_PHYSICAL: u32 = 0;
pub const BATCH_KIND_VIRTUAL: u32 = 1;
#[cfg(test)]
const BATCH_REQ_STATUS_EMPTY: u32 = 0;
pub const BATCH_REQ_STATUS_OK: u32 = 1;
const BATCH_REQ_STATUS_FAILED: u32 = 2;
const ARMED_IDLE_DELAY_100NS: i64 = -100;
const UNARMED_IDLE_DELAY_100NS: i64 = -100_000;
const SLOT_IDLE: u64 = 0;
const SLOT_SUBMITTING: u64 = 1;
const SLOT_PENDING: u64 = 2;
const SLOT_READY: u64 = 3;
const BATCH_REG_UNREGISTERED: u64 = 0;
const BATCH_REG_REGISTERING: u64 = 1;
const BATCH_REG_READY: u64 = 2;
const BATCH_REG_FAILED: u64 = 3;
const BATCH_REG_UNREGISTERING: u64 = 4;

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
static WORKER_HANDLE: AtomicU64 = AtomicU64::new(0);
static mut RESULT_BYTES: [u8; MAX_READ_SIZE] = [0; MAX_READ_SIZE];
static BATCH_REG_STATE: AtomicU64 = AtomicU64::new(BATCH_REG_UNREGISTERED);
static BATCH_REG_PID: AtomicU64 = AtomicU64::new(0);
static BATCH_REG_USER_VA: AtomicU64 = AtomicU64::new(0);
static BATCH_REG_SIZE: AtomicU64 = AtomicU64::new(0);
static BATCH_REG_MDL: AtomicU64 = AtomicU64::new(0);
static BATCH_REG_SYSTEM_VA: AtomicU64 = AtomicU64::new(0);
static BATCH_REG_EPROCESS: AtomicU64 = AtomicU64::new(0);
static BATCH_REG_GENERATION: AtomicU64 = AtomicU64::new(0);
static BATCH_REG_PROCESSED: AtomicU64 = AtomicU64::new(0);
static BATCH_REG_FAILURES: AtomicU64 = AtomicU64::new(0);
static BATCH_PROCESSING: AtomicBool = AtomicBool::new(false);

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

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BatchHeader {
    magic: u32,
    version: u32,
    state: u32,
    request_count: u32,
    sequence: u32,
    processed: u32,
    failures: u32,
    result_bytes: u32,
    capacity: u32,
    flags: u32,
    last_status: u32,
    reserved_u32: u32,
    reserved: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BatchRequest {
    kind: u32,
    size: u32,
    status: u32,
    out_offset: u32,
    address: u64,
    cr3: u64,
}

const _: () = assert!(core::mem::size_of::<BatchHeader>() == BATCH_HEADER_BYTES);
const _: () = assert!(core::mem::size_of::<BatchRequest>() == BATCH_REQUEST_BYTES);

#[cfg(not(test))]
extern "C" {
    fn HvProbeAndLockPagesSafe(mdl: PMDL, access_mode: i32, operation: i32) -> i32;
}

#[cfg(not(test))]
fn probe_and_lock_pages_safe(mdl: PMDL) -> bool {
    unsafe {
        HvProbeAndLockPagesSafe(
            mdl,
            _MODE::UserMode as i32,
            _LOCK_OPERATION::IoModifyAccess as i32,
        ) == STATUS_SUCCESS
    }
}

#[cfg(test)]
fn probe_and_lock_pages_safe(mdl: PMDL) -> bool {
    !mdl.is_null()
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

pub fn request_batch_buffer_registration(user_va: u64, size: usize) -> u64 {
    let pid = unsafe { PsGetCurrentProcessId() as u64 };
    request_batch_buffer_registration_for_pid(pid, user_va, size)
}

fn request_batch_buffer_registration_for_pid(pid: u64, user_va: u64, size: usize) -> u64 {
    if !worker_started() || pid == 0 || !batch_buffer_bounds_are_valid(user_va, size) {
        return STATUS_FAILED;
    }

    if BATCH_REG_STATE.load(Ordering::Acquire) == BATCH_REG_READY
        && BATCH_REG_PID.load(Ordering::Acquire) == pid
        && BATCH_REG_USER_VA.load(Ordering::Acquire) == user_va
        && BATCH_REG_SIZE.load(Ordering::Acquire) == size as u64
    {
        return STATUS_OK;
    }

    match BATCH_REG_STATE.compare_exchange(
        BATCH_REG_UNREGISTERED,
        BATCH_REG_REGISTERING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            BATCH_REG_PID.store(pid, Ordering::Release);
            BATCH_REG_USER_VA.store(user_va, Ordering::Release);
            BATCH_REG_SIZE.store(size as u64, Ordering::Release);
            READ_PENDING
        }
        Err(BATCH_REG_REGISTERING) | Err(BATCH_REG_UNREGISTERING) => READ_PENDING,
        Err(BATCH_REG_FAILED) => {
            BATCH_REG_STATE.store(BATCH_REG_UNREGISTERED, Ordering::Release);
            STATUS_FAILED
        }
        Err(BATCH_REG_READY) => match BATCH_REG_STATE.compare_exchange(
            BATCH_REG_READY,
            BATCH_REG_UNREGISTERING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => READ_PENDING,
            Err(BATCH_REG_REGISTERING) | Err(BATCH_REG_UNREGISTERING) => READ_PENDING,
            Err(BATCH_REG_FAILED) => {
                BATCH_REG_STATE.store(BATCH_REG_UNREGISTERED, Ordering::Release);
                STATUS_FAILED
            }
            Err(_) => STATUS_FAILED,
        },
        Err(_) => STATUS_FAILED,
    }
}

pub fn request_batch_buffer_unregister() -> u64 {
    match BATCH_REG_STATE.compare_exchange(
        BATCH_REG_READY,
        BATCH_REG_UNREGISTERING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => READ_PENDING,
        Err(BATCH_REG_UNREGISTERED) => STATUS_OK,
        Err(BATCH_REG_UNREGISTERING) | Err(BATCH_REG_REGISTERING) => READ_PENDING,
        Err(_) => STATUS_FAILED,
    }
}

pub fn batch_state() -> u64 {
    BATCH_REG_STATE.load(Ordering::Acquire)
}

fn batch_buffer_bounds_are_valid(user_va: u64, size: usize) -> bool {
    if user_va == 0
        || user_va & 0xfff != 0
        || size != BATCH_BUFFER_BYTES
        || size > BATCH_BUFFER_MAX_BYTES
        || size & 0xfff != 0
    {
        return false;
    }

    let Some(end) = user_va.checked_add(size as u64) else {
        return false;
    };
    end <= USER_VA_LIMIT
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

pub fn read_result_quad(seq: u64, offset: u64) -> [u64; 4] {
    [
        read_result_word(seq, offset),
        read_result_word(seq, offset.saturating_add(8)),
        read_result_word(seq, offset.saturating_add(16)),
        read_result_word(seq, offset.saturating_add(24)),
    ]
}

pub fn read_result_wide(seq: u64, offset: u64) -> [u64; 8] {
    [
        read_result_word(seq, offset),
        read_result_word(seq, offset.saturating_add(8)),
        read_result_word(seq, offset.saturating_add(16)),
        read_result_word(seq, offset.saturating_add(24)),
        read_result_word(seq, offset.saturating_add(32)),
        read_result_word(seq, offset.saturating_add(40)),
        read_result_word(seq, offset.saturating_add(48)),
        read_result_word(seq, offset.saturating_add(56)),
    ]
}

pub fn read_result_xmm(seq: u64, offset: u64) -> Option<[M128A; XMM_RESULT_REGS]> {
    if REQUEST_SEQ.load(Ordering::Acquire) != seq
        || DONE_SEQ.load(Ordering::Acquire) != seq
        || SLOT_STATE.load(Ordering::Acquire) != SLOT_READY
        || RESULT_STATUS.load(Ordering::Relaxed) != STATUS_OK
    {
        return None;
    }

    let size = RESULT_SIZE.load(Ordering::Acquire) as usize;
    let offset = offset as usize;
    if offset >= size || offset >= MAX_READ_SIZE {
        return None;
    }

    let mut out = [M128A::default(); XMM_RESULT_REGS];
    let mut current = offset;
    for slot in &mut out {
        slot.Low = read_result_word(seq, current as u64);
        slot.High = read_result_word(seq, current.saturating_add(8) as u64) as i64;
        current = current.saturating_add(16);
        if current >= offset.saturating_add(XMM_RESULT_BYTES) {
            break;
        }
    }
    Some(out)
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

pub fn copy_result_to_guest_buffer_and_release(
    seq: u64,
    guest_cr3: u64,
    dst_va: u64,
    capacity: usize,
) -> u64 {
    copy_result_to_guest_buffer_and_release_with(
        seq,
        guest_cr3,
        dst_va,
        capacity,
        translate_user_writable_va_to_pa,
        write_phys_from_ptr_mapped,
    )
}

fn copy_result_to_guest_buffer_and_release_with(
    seq: u64,
    guest_cr3: u64,
    dst_va: u64,
    capacity: usize,
    mut translate: impl FnMut(u64, u64) -> Option<u64>,
    mut write_phys: impl FnMut(u64, *const u8, usize) -> bool,
) -> u64 {
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
    if RESULT_STATUS.load(Ordering::Relaxed) != STATUS_OK {
        return 0;
    }

    let size = RESULT_SIZE.load(Ordering::Acquire) as usize;
    if !shared_copy_bounds_are_valid(dst_va, capacity, size) || guest_cr3 == 0 {
        return 0;
    }

    let mut copied = 0usize;
    while copied < size {
        let cur_va = dst_va.wrapping_add(copied as u64);
        let page_left = 0x1000usize - (cur_va as usize & 0xFFF);
        let chunk = (size - copied).min(page_left);
        let Some(dst_pa) = translate(guest_cr3, cur_va) else {
            return 0;
        };
        let src = unsafe { result_bytes_ptr().add(copied) }.cast_const();
        if !write_phys(dst_pa, src, chunk) {
            return 0;
        }
        copied += chunk;
    }

    SLOT_STATE.store(SLOT_IDLE, Ordering::Release);
    size as u64
}

fn batch_header_ptr(base: *mut u8) -> *mut BatchHeader {
    base.cast::<BatchHeader>()
}

fn batch_header_state_ptr(base: *mut u8) -> *mut u32 {
    unsafe { core::ptr::addr_of_mut!((*batch_header_ptr(base)).state) }
}

fn batch_header_processed_ptr(base: *mut u8) -> *mut u32 {
    unsafe { core::ptr::addr_of_mut!((*batch_header_ptr(base)).processed) }
}

fn batch_header_failures_ptr(base: *mut u8) -> *mut u32 {
    unsafe { core::ptr::addr_of_mut!((*batch_header_ptr(base)).failures) }
}

fn batch_header_result_bytes_ptr(base: *mut u8) -> *mut u32 {
    unsafe { core::ptr::addr_of_mut!((*batch_header_ptr(base)).result_bytes) }
}

fn batch_header_last_status_ptr(base: *mut u8) -> *mut u32 {
    unsafe { core::ptr::addr_of_mut!((*batch_header_ptr(base)).last_status) }
}

fn batch_request_ptr(base: *mut u8, index: usize) -> *mut BatchRequest {
    unsafe { base.add(BATCH_HEADER_BYTES + index * BATCH_REQUEST_BYTES) }.cast::<BatchRequest>()
}

fn batch_result_ptr(base: *mut u8, offset: usize) -> *mut u8 {
    unsafe { base.add(offset) }
}

fn batch_request_is_valid(req: &BatchRequest) -> bool {
    matches!(req.kind, BATCH_KIND_PHYSICAL | BATCH_KIND_VIRTUAL)
        && (1..=MAX_READ_SIZE as u32).contains(&req.size)
        && (req.kind != BATCH_KIND_VIRTUAL || req.cr3 != 0)
}

fn process_batch_buffer() -> u64 {
    let Some(_guard) = try_enter_batch_processing() else {
        return READ_PENDING;
    };

    let system_va = BATCH_REG_SYSTEM_VA.load(Ordering::Acquire) as *mut u8;
    let size = BATCH_REG_SIZE.load(Ordering::Acquire) as usize;
    if system_va.is_null() || size == 0 {
        return STATUS_FAILED;
    }

    process_batch_buffer_with(system_va, size, |req, dst| {
        let size = req.size as usize;
        let read = match req.kind {
            BATCH_KIND_PHYSICAL => read_phys_to_ptr(req.address, dst.as_mut_ptr(), size),
            BATCH_KIND_VIRTUAL => read_virtual_to_ptr(req.cr3, req.address, dst.as_mut_ptr(), size),
            _ => None,
        };
        read == Some(size)
    })
}

struct BatchProcessingGuard;

impl Drop for BatchProcessingGuard {
    fn drop(&mut self) {
        BATCH_PROCESSING.store(false, Ordering::Release);
    }
}

fn try_enter_batch_processing() -> Option<BatchProcessingGuard> {
    BATCH_PROCESSING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| BatchProcessingGuard)
}

fn process_batch_buffer_with(
    base: *mut u8,
    len: usize,
    mut reader: impl FnMut(&BatchRequest, &mut [u8]) -> bool,
) -> u64 {
    if base.is_null() || len < BATCH_BUFFER_BYTES {
        return STATUS_FAILED;
    }

    let header_ptr = batch_header_ptr(base);
    let header = unsafe { core::ptr::read_volatile(header_ptr) };
    if header.magic != BATCH_MAGIC
        || header.version != BATCH_VERSION
        || header.state != BATCH_STATE_SUBMITTED
        || header.request_count == 0
        || header.request_count as usize > BATCH_MAX_REQUESTS
        || header.capacity as usize > len
        || header.capacity as usize != BATCH_BUFFER_BYTES
    {
        return STATUS_FAILED;
    }

    let mut data_cursor = BATCH_DATA_OFFSET;
    let mut processed = 0u32;
    let mut failures = 0u32;

    for index in 0..header.request_count as usize {
        let request_ptr = batch_request_ptr(base, index);
        let mut req = unsafe { core::ptr::read_volatile(request_ptr) };
        req.status = BATCH_REQ_STATUS_FAILED;
        req.out_offset = 0;

        let size = req.size as usize;
        let next_cursor = data_cursor.checked_add(size).unwrap_or(usize::MAX);
        if batch_request_is_valid(&req) && next_cursor <= len {
            let dst = unsafe {
                core::slice::from_raw_parts_mut(batch_result_ptr(base, data_cursor), size)
            };
            if reader(&req, dst) {
                req.out_offset = data_cursor as u32;
                req.status = BATCH_REQ_STATUS_OK;
                data_cursor = next_cursor;
                processed = processed.saturating_add(1);
            } else {
                failures = failures.saturating_add(1);
            }
        } else {
            failures = failures.saturating_add(1);
        }

        unsafe {
            core::ptr::write_volatile(request_ptr, req);
        }
    }

    let current = unsafe { core::ptr::read_volatile(header_ptr) };
    if current.sequence != header.sequence || current.state != BATCH_STATE_SUBMITTED {
        return READ_PENDING;
    }

    let result_bytes = data_cursor.saturating_sub(BATCH_DATA_OFFSET) as u32;
    let last_status = if failures == 0 {
        STATUS_OK as u32
    } else {
        STATUS_FAILED as u32
    };

    unsafe {
        core::ptr::write_volatile(batch_header_processed_ptr(base), processed);
        core::ptr::write_volatile(batch_header_failures_ptr(base), failures);
        core::ptr::write_volatile(batch_header_result_bytes_ptr(base), result_bytes);
        core::ptr::write_volatile(batch_header_last_status_ptr(base), last_status);
        core::sync::atomic::fence(Ordering::Release);
        core::ptr::write_volatile(batch_header_state_ptr(base), BATCH_STATE_DONE);
    }

    BATCH_REG_PROCESSED.fetch_add(processed as u64, Ordering::Relaxed);
    BATCH_REG_FAILURES.fetch_add(failures as u64, Ordering::Relaxed);
    STATUS_OK
}

fn shared_copy_bounds_are_valid(dst_va: u64, capacity: usize, size: usize) -> bool {
    if dst_va == 0
        || size == 0
        || size > MAX_READ_SIZE
        || capacity < size
        || capacity > MAX_READ_SIZE
    {
        return false;
    }

    let Some(end) = dst_va.checked_add(size as u64) else {
        return false;
    };
    end <= USER_VA_LIMIT
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
        13 => BATCH_REG_STATE.load(Ordering::Acquire),
        14 => BATCH_REG_GENERATION.load(Ordering::Acquire),
        15 => BATCH_REG_PROCESSED.load(Ordering::Acquire),
        16 => BATCH_REG_FAILURES.load(Ordering::Acquire),
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
    WORKER_HANDLE.store(handle as u64, Ordering::Release);
    true
}

pub fn stop_worker() {
    WORKER_SHUTDOWN.store(true, Ordering::Release);
    request_batch_cleanup_on_worker_exit();
    let handle = WORKER_HANDLE.swap(0, Ordering::AcqRel) as HANDLE;
    if !handle.is_null() {
        unsafe {
            let _ = ZwWaitForSingleObject(handle, false as _, null_mut());
            let _ = ZwClose(handle);
        }
    }
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

        match BATCH_REG_STATE.load(Ordering::Acquire) {
            BATCH_REG_REGISTERING => {
                register_batch_buffer_from_worker();
                idle_spins = 0;
                continue;
            }
            BATCH_REG_UNREGISTERING => {
                cleanup_batch_registration();
                BATCH_REG_STATE.store(BATCH_REG_UNREGISTERED, Ordering::Release);
                idle_spins = 0;
                continue;
            }
            BATCH_REG_READY => {
                let _ = process_batch_buffer();
            }
            _ => {}
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
        core::hint::spin_loop();
    }

    cleanup_batch_registration();
    BATCH_REG_STATE.store(BATCH_REG_UNREGISTERED, Ordering::Release);
    mark_worker_started(false);
    let _ = PsTerminateSystemThread(STATUS_SUCCESS);
}

fn register_batch_buffer_from_worker() {
    let user_va = BATCH_REG_USER_VA.load(Ordering::Acquire);
    let size = BATCH_REG_SIZE.load(Ordering::Acquire) as usize;
    let pid = BATCH_REG_PID.load(Ordering::Acquire);
    if pid == 0 || !batch_buffer_bounds_are_valid(user_va, size) {
        BATCH_REG_STATE.store(BATCH_REG_FAILED, Ordering::Release);
        return;
    }

    let mut process: PEPROCESS = null_mut();
    let lookup_status =
        unsafe { PsLookupProcessByProcessId(pid as HANDLE, &mut process as *mut _) };
    if !NT_SUCCESS(lookup_status) || process.is_null() {
        BATCH_REG_STATE.store(BATCH_REG_FAILED, Ordering::Release);
        return;
    }

    let mut apc_state = _KAPC_STATE::default();
    let mut locked = false;
    let mut mapped: PVOID = null_mut();

    unsafe {
        KeStackAttachProcess(process as PRKPROCESS, &mut apc_state);
    }

    let mdl = unsafe {
        IoAllocateMdl(
            user_va as PVOID,
            size as u32,
            false as _,
            false as _,
            null_mut(),
        )
    };

    unsafe {
        if !mdl.is_null() {
            if probe_and_lock_pages_safe(mdl) {
                locked = true;
                mapped = MmMapLockedPagesSpecifyCache(
                    mdl,
                    _MODE::KernelMode as _,
                    _MEMORY_CACHING_TYPE::MmCached,
                    null_mut(),
                    0,
                    (_MM_PAGE_PRIORITY::HighPagePriority as u32 | MdlMappingNoExecute) as u32,
                );
            }
        }

        KeUnstackDetachProcess(&mut apc_state);
    }

    if mdl.is_null() || mapped.is_null() {
        unsafe {
            if locked {
                MmUnlockPages(mdl);
            }
            if !mdl.is_null() {
                IoFreeMdl(mdl);
            }
            ObDereferenceObjectDeferDelete(process as PVOID);
        }
        BATCH_REG_STATE.store(BATCH_REG_FAILED, Ordering::Release);
        return;
    }

    BATCH_REG_MDL.store(mdl as u64, Ordering::Release);
    BATCH_REG_SYSTEM_VA.store(mapped as u64, Ordering::Release);
    BATCH_REG_EPROCESS.store(process as u64, Ordering::Release);
    BATCH_REG_GENERATION.fetch_add(1, Ordering::AcqRel);
    BATCH_REG_PROCESSED.store(0, Ordering::Release);
    BATCH_REG_FAILURES.store(0, Ordering::Release);
    BATCH_REG_STATE.store(BATCH_REG_READY, Ordering::Release);
}

fn request_batch_cleanup_on_worker_exit() {
    loop {
        match BATCH_REG_STATE.load(Ordering::Acquire) {
            BATCH_REG_UNREGISTERED | BATCH_REG_UNREGISTERING => return,
            state => {
                if BATCH_REG_STATE
                    .compare_exchange(
                        state,
                        BATCH_REG_UNREGISTERING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return;
                }
            }
        }
    }
}

fn cleanup_batch_registration() {
    let mapped = BATCH_REG_SYSTEM_VA.swap(0, Ordering::AcqRel) as PVOID;
    let mdl = BATCH_REG_MDL.swap(0, Ordering::AcqRel) as PMDL;
    let process = BATCH_REG_EPROCESS.swap(0, Ordering::AcqRel) as PVOID;

    unsafe {
        if !mapped.is_null() && !mdl.is_null() {
            MmUnmapLockedPages(mapped, mdl);
        }
        if !mdl.is_null() {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
        }
        if !process.is_null() {
            ObDereferenceObjectDeferDelete(process);
        }
    }
    BATCH_REG_USER_VA.store(0, Ordering::Release);
    BATCH_REG_SIZE.store(0, Ordering::Release);
    BATCH_REG_PID.store(0, Ordering::Release);
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

fn read_virtual_to_ptr(cr3: u64, va: u64, dst: *mut u8, size: usize) -> Option<usize> {
    if cr3 == 0 || dst.is_null() || !(1..=MAX_READ_SIZE).contains(&size) {
        return None;
    }

    let mut copied = 0usize;
    while copied < size {
        let cur_va = va.wrapping_add(copied as u64);
        let page_left = 0x1000usize - (cur_va as usize & 0xFFF);
        let chunk = (size - copied).min(page_left);
        let pa = translate_va_to_pa(cr3, cur_va)?;
        let cur_dst = unsafe { dst.add(copied) };
        read_phys_to_ptr(pa, cur_dst, chunk)?;
        copied += chunk;
    }

    Some(copied)
}

fn read_virtual_into_result(cr3: u64, va: u64, size: usize) -> Option<usize> {
    read_virtual_to_ptr(cr3, va, result_bytes_ptr(), size)
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

fn entry_allows_user_write(entry: u64) -> bool {
    entry & 0x7 == 0x7
}

fn translate_user_writable_va_to_pa(cr3: u64, va: u64) -> Option<u64> {
    if va >= USER_VA_LIMIT {
        return None;
    }

    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;
    let offset = va & 0xFFF;

    let pml4e = read_page_table_entry(pml4_base + pml4_idx * 8)?;
    if !entry_allows_user_write(pml4e) {
        return None;
    }

    let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
    let pdpte = read_page_table_entry(pdpt_base + pdpt_idx * 8)?;
    if !entry_allows_user_write(pdpte) {
        return None;
    }
    if pdpte & 0x80 != 0 {
        return Some((pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF));
    }

    let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
    let pde = read_page_table_entry(pd_base + pd_idx * 8)?;
    if !entry_allows_user_write(pde) {
        return None;
    }
    if pde & 0x80 != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }

    let pt_base = pde & 0x000F_FFFF_FFFF_F000;
    let pte = read_page_table_entry(pt_base + pt_idx * 8)?;
    if !entry_allows_user_write(pte) {
        return None;
    }

    Some((pte & 0x000F_FFFF_FFFF_F000) | offset)
}

fn physical_page_mapping_window(dst_pa: u64, size: usize) -> Option<(u64, usize, usize)> {
    if size == 0 || size > MAX_READ_SIZE {
        return None;
    }

    let page_offset = (dst_pa & 0xFFF) as usize;
    let map_size = page_offset.checked_add(size)?;
    if map_size > 0x1000 {
        return None;
    }

    Some((dst_pa & !0xFFF, page_offset, map_size))
}

fn write_phys_from_ptr_mapped(dst_pa: u64, src: *const u8, size: usize) -> bool {
    if src.is_null() {
        return false;
    }
    let Some((map_pa, page_offset, map_size)) = physical_page_mapping_window(dst_pa, size) else {
        return false;
    };

    let mapped = unsafe {
        MmMapIoSpaceEx(
            PHYSICAL_ADDRESS {
                QuadPart: map_pa as i64,
            },
            map_size as u64,
            PAGE_READWRITE,
        )
    };
    if mapped.is_null() {
        return false;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(src, (mapped as *mut u8).add(page_offset), size);
        MmUnmapIoSpace(mapped, map_size as u64);
    }
    true
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
    WORKER_HANDLE.store(0, Ordering::Relaxed);
    BATCH_REG_STATE.store(BATCH_REG_UNREGISTERED, Ordering::Relaxed);
    BATCH_REG_PID.store(0, Ordering::Relaxed);
    BATCH_REG_USER_VA.store(0, Ordering::Relaxed);
    BATCH_REG_SIZE.store(0, Ordering::Relaxed);
    BATCH_REG_MDL.store(0, Ordering::Relaxed);
    BATCH_REG_SYSTEM_VA.store(0, Ordering::Relaxed);
    BATCH_REG_EPROCESS.store(0, Ordering::Relaxed);
    BATCH_REG_GENERATION.store(0, Ordering::Relaxed);
    BATCH_REG_PROCESSED.store(0, Ordering::Relaxed);
    BATCH_REG_FAILURES.store(0, Ordering::Relaxed);
    BATCH_PROCESSING.store(false, Ordering::Relaxed);
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
#[derive(Clone, Copy)]
struct BatchRequestForTest {
    kind: u32,
    cr3: u64,
    address: u64,
    size: u32,
}

#[cfg(test)]
fn prepare_batch_for_test(buffer: &mut [u8], requests: &[BatchRequestForTest]) {
    assert!(buffer.len() >= BATCH_BUFFER_BYTES);
    let base = buffer.as_mut_ptr();
    let header = BatchHeader {
        magic: BATCH_MAGIC,
        version: BATCH_VERSION,
        state: BATCH_STATE_SUBMITTED,
        request_count: requests.len() as u32,
        sequence: 1,
        processed: 0,
        failures: 0,
        result_bytes: 0,
        capacity: BATCH_BUFFER_BYTES as u32,
        flags: 0,
        last_status: 0,
        reserved_u32: 0,
        reserved: [0; 2],
    };
    unsafe {
        core::ptr::write(batch_header_ptr(base), header);
    }

    for (index, req) in requests.iter().enumerate() {
        let entry = BatchRequest {
            kind: req.kind,
            size: req.size,
            status: BATCH_REQ_STATUS_EMPTY,
            out_offset: 0,
            address: req.address,
            cr3: req.cr3,
        };
        unsafe {
            core::ptr::write(batch_request_ptr(base, index), entry);
        }
    }
}

#[cfg(test)]
fn batch_header_state_for_test(buffer: &[u8]) -> u32 {
    unsafe { core::ptr::read(batch_header_ptr(buffer.as_ptr() as *mut u8)).state }
}

#[cfg(test)]
fn batch_header_sequence_for_test(buffer: &[u8]) -> u32 {
    unsafe { core::ptr::read(batch_header_ptr(buffer.as_ptr() as *mut u8)).sequence }
}

#[cfg(test)]
fn batch_header_processed_for_test(buffer: &[u8]) -> u32 {
    unsafe { core::ptr::read(batch_header_ptr(buffer.as_ptr() as *mut u8)).processed }
}

#[cfg(test)]
fn batch_request_for_test(buffer: &[u8], index: usize) -> BatchRequest {
    unsafe { core::ptr::read(batch_request_ptr(buffer.as_ptr() as *mut u8, index)) }
}

#[cfg(test)]
fn batch_request_status_for_test(buffer: &[u8], index: usize) -> u32 {
    batch_request_for_test(buffer, index).status
}

#[cfg(test)]
fn batch_result_for_test(buffer: &[u8], index: usize) -> &[u8] {
    let req = batch_request_for_test(buffer, index);
    let offset = req.out_offset as usize;
    let size = req.size as usize;
    &buffer[offset..offset + size]
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
    fn batch_buffer_bounds_require_user_page_aligned_locked_region() {
        let _guard = test_lock();

        assert!(batch_buffer_bounds_are_valid(0x1000, BATCH_BUFFER_BYTES));
        assert!(!batch_buffer_bounds_are_valid(0x1001, BATCH_BUFFER_BYTES));
        assert!(!batch_buffer_bounds_are_valid(
            0x1000,
            BATCH_BUFFER_BYTES - 1
        ));
        assert!(!batch_buffer_bounds_are_valid(
            0x1000,
            BATCH_BUFFER_MAX_BYTES + 0x1000
        ));
        assert!(!batch_buffer_bounds_are_valid(
            USER_VA_LIMIT,
            BATCH_BUFFER_BYTES
        ));
    }

    #[test]
    fn batch_processor_writes_multiple_results_into_shared_region() {
        let _guard = test_lock();
        let mut buffer = [0u8; BATCH_BUFFER_BYTES];
        prepare_batch_for_test(
            &mut buffer,
            &[
                BatchRequestForTest {
                    kind: BATCH_KIND_VIRTUAL,
                    cr3: 0x1234_5000,
                    address: 0x7ff6_1000,
                    size: 4,
                },
                BatchRequestForTest {
                    kind: BATCH_KIND_PHYSICAL,
                    cr3: 0,
                    address: 0x2000,
                    size: 8,
                },
            ],
        );

        let status = process_batch_buffer_with(buffer.as_mut_ptr(), buffer.len(), |req, dst| {
            for (i, byte) in dst.iter_mut().enumerate() {
                *byte = (req.address as u8).wrapping_add(i as u8);
            }
            true
        });

        assert_eq!(status, STATUS_OK);
        assert_eq!(batch_header_state_for_test(&buffer), BATCH_STATE_DONE);
        assert_eq!(batch_header_processed_for_test(&buffer), 2);
        assert_eq!(
            batch_request_status_for_test(&buffer, 0),
            BATCH_REQ_STATUS_OK
        );
        assert_eq!(
            batch_request_status_for_test(&buffer, 1),
            BATCH_REQ_STATUS_OK
        );
        assert_eq!(batch_result_for_test(&buffer, 0), &[0x00, 0x01, 0x02, 0x03]);
        assert_eq!(
            batch_result_for_test(&buffer, 1),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );
    }

    #[test]
    fn batch_processor_does_not_touch_buffer_when_already_active() {
        let _guard = test_lock();
        reset_for_test();
        let mut buffer = [0u8; BATCH_BUFFER_BYTES];
        prepare_batch_for_test(
            &mut buffer,
            &[BatchRequestForTest {
                kind: BATCH_KIND_PHYSICAL,
                cr3: 0,
                address: 0x2000,
                size: 4,
            }],
        );
        BATCH_REG_SYSTEM_VA.store(buffer.as_mut_ptr() as u64, Ordering::Release);
        BATCH_REG_SIZE.store(BATCH_BUFFER_BYTES as u64, Ordering::Release);
        BATCH_PROCESSING.store(true, Ordering::Release);

        let status = process_batch_buffer();

        BATCH_PROCESSING.store(false, Ordering::Release);
        assert_eq!(status, READ_PENDING);
        assert_eq!(batch_header_state_for_test(&buffer), BATCH_STATE_SUBMITTED);
        assert_eq!(
            batch_request_status_for_test(&buffer, 0),
            BATCH_REQ_STATUS_EMPTY
        );
    }

    #[test]
    fn batch_processor_does_not_publish_stale_completion_after_sequence_changes() {
        let _guard = test_lock();
        let mut buffer = [0u8; BATCH_BUFFER_BYTES];
        prepare_batch_for_test(
            &mut buffer,
            &[BatchRequestForTest {
                kind: BATCH_KIND_PHYSICAL,
                cr3: 0,
                address: 0x2000,
                size: 4,
            }],
        );
        let base = buffer.as_mut_ptr() as usize;

        let status = process_batch_buffer_with(buffer.as_mut_ptr(), buffer.len(), |_req, dst| {
            dst.copy_from_slice(&[1, 2, 3, 4]);
            unsafe {
                (*batch_header_ptr(base as *mut u8)).sequence = 2;
                (*batch_header_ptr(base as *mut u8)).state = BATCH_STATE_SUBMITTED;
            }
            true
        });

        assert_eq!(status, READ_PENDING);
        assert_eq!(batch_header_sequence_for_test(&buffer), 2);
        assert_eq!(batch_header_state_for_test(&buffer), BATCH_STATE_SUBMITTED);
    }

    #[test]
    fn batch_registration_reuses_matching_ready_buffer() {
        let _guard = test_lock();
        reset_for_test();
        BATCH_REG_STATE.store(BATCH_REG_READY, Ordering::Release);
        BATCH_REG_PID.store(0x1234, Ordering::Release);
        BATCH_REG_USER_VA.store(0x2000, Ordering::Release);
        BATCH_REG_SIZE.store(BATCH_BUFFER_BYTES as u64, Ordering::Release);

        let status = request_batch_buffer_registration_for_pid(0x1234, 0x2000, BATCH_BUFFER_BYTES);

        assert_eq!(status, STATUS_OK);
        assert_eq!(BATCH_REG_STATE.load(Ordering::Acquire), BATCH_REG_READY);
    }

    #[test]
    fn batch_registration_replaces_stale_ready_buffer_before_retry() {
        let _guard = test_lock();
        reset_for_test();
        BATCH_REG_STATE.store(BATCH_REG_READY, Ordering::Release);
        BATCH_REG_PID.store(0x1234, Ordering::Release);
        BATCH_REG_USER_VA.store(0x2000, Ordering::Release);
        BATCH_REG_SIZE.store(BATCH_BUFFER_BYTES as u64, Ordering::Release);

        let status = request_batch_buffer_registration_for_pid(0x5678, 0x3000, BATCH_BUFFER_BYTES);

        assert_eq!(status, READ_PENDING);
        assert_eq!(
            BATCH_REG_STATE.load(Ordering::Acquire),
            BATCH_REG_UNREGISTERING
        );
    }

    #[test]
    fn stop_worker_defers_batch_cleanup_to_worker_thread() {
        let _guard = test_lock();
        reset_for_test();
        BATCH_REG_STATE.store(BATCH_REG_READY, Ordering::Release);
        BATCH_REG_SYSTEM_VA.store(0x1000, Ordering::Release);
        BATCH_REG_MDL.store(0x2000, Ordering::Release);
        BATCH_REG_EPROCESS.store(0x3000, Ordering::Release);

        stop_worker();

        assert!(WORKER_SHUTDOWN.load(Ordering::Acquire));
        assert!(!worker_started());
        assert_eq!(
            BATCH_REG_STATE.load(Ordering::Acquire),
            BATCH_REG_UNREGISTERING
        );
        assert_eq!(BATCH_REG_SYSTEM_VA.load(Ordering::Acquire), 0x1000);
        assert_eq!(BATCH_REG_MDL.load(Ordering::Acquire), 0x2000);
        assert_eq!(BATCH_REG_EPROCESS.load(Ordering::Acquire), 0x3000);
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
    fn bulk_result_quad_returns_four_words_without_releasing_slot() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 32);
        assert_ne!(seq, 0);

        let bytes = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        complete_bytes_for_test(seq, &bytes, true);

        assert_eq!(poll_read_info(seq), 32);
        assert_eq!(
            read_result_quad(seq, 0),
            [
                0x0807_0605_0403_0201,
                0x100f_0e0d_0c0b_0a09,
                0x1817_1615_1413_1211,
                0x201f_1e1d_1c1b_1a19,
            ]
        );
        assert_eq!(submit_virtual_read(0x1234_5000, 0x7ff6_1234_5688, 8), 0);
        assert_eq!(release_read_result(seq), 0);
    }

    #[test]
    fn bulk_result_wide_returns_eight_words_without_releasing_slot() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 64);
        assert_ne!(seq, 0);

        let mut bytes = [0u8; 64];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        complete_bytes_for_test(seq, &bytes, true);

        assert_eq!(poll_read_info(seq), 64);
        assert_eq!(
            read_result_wide(seq, 0),
            [
                0x0807_0605_0403_0201,
                0x100f_0e0d_0c0b_0a09,
                0x1817_1615_1413_1211,
                0x201f_1e1d_1c1b_1a19,
                0x2827_2625_2423_2221,
                0x302f_2e2d_2c2b_2a29,
                0x3837_3635_3433_3231,
                0x403f_3e3d_3c3b_3a39,
            ]
        );
        assert_eq!(submit_virtual_read(0x1234_5000, 0x7ff6_1234_5688, 8), 0);
        assert_eq!(release_read_result(seq), 0);
    }

    #[test]
    fn bulk_result_xmm_returns_sixteen_vectors_without_releasing_slot() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 256);
        assert_ne!(seq, 0);

        let mut bytes = [0u8; 256];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        complete_bytes_for_test(seq, &bytes, true);

        let vectors = read_result_xmm(seq, 0).unwrap();
        assert_eq!(poll_read_info(seq), 256);
        assert_eq!(vectors[0].Low, 0x0706_0504_0302_0100);
        assert_eq!(vectors[0].High as u64, 0x0f0e_0d0c_0b0a_0908);
        assert_eq!(vectors[15].Low, 0xf7f6_f5f4_f3f2_f1f0);
        assert_eq!(vectors[15].High as u64, 0xfffe_fdfc_fbfa_f9f8);
        assert_eq!(submit_virtual_read(0x1234_5000, 0x7ff6_1234_5688, 8), 0);
        assert_eq!(release_read_result(seq), 0);
    }

    #[test]
    fn shared_copy_pending_returns_pending_without_releasing_slot() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 16);
        let status = copy_result_to_guest_buffer_and_release_with(
            seq,
            0x1234_5000,
            0x1000,
            16,
            |_, _| Some(0x2000),
            |_, _, _| true,
        );

        assert_eq!(status, READ_PENDING);
        assert_eq!(debug_state(11), SLOT_PENDING);
    }

    #[test]
    fn shared_copy_rejects_small_capacity_and_keeps_result_ready_for_explicit_release() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 16);
        complete_bytes_for_test(
            seq,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            true,
        );

        let status = copy_result_to_guest_buffer_and_release_with(
            seq,
            0x1234_5000,
            0x1000,
            8,
            |_, _| Some(0x2000),
            |_, _, _| true,
        );

        assert_eq!(status, 0);
        assert_eq!(debug_state(11), SLOT_READY);
        assert_eq!(read_result_word(seq, 0), 0x0807_0605_0403_0201);
        assert_eq!(release_read_result(seq), 0);
    }

    #[test]
    fn shared_copy_writes_result_and_releases_slot() {
        let _guard = test_lock();
        reset_for_test();

        let seq = submit_virtual_read(0x1234_5000, 0x7ff6_1234_5678, 16);
        complete_bytes_for_test(
            seq,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            true,
        );

        let mut written = [0u8; 16];
        let status = copy_result_to_guest_buffer_and_release_with(
            seq,
            0x1234_5000,
            0x1000,
            16,
            |_, va| (va == 0x1000).then_some(0x2000),
            |pa, src, size| {
                if pa != 0x2000 || size != written.len() {
                    return false;
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(src, written.as_mut_ptr(), size);
                }
                true
            },
        );

        assert_eq!(status, 16);
        assert_eq!(
            written,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        assert_eq!(debug_state(11), SLOT_IDLE);
        assert_ne!(submit_virtual_read(0x1234_5000, 0x7ff6_1234_5688, 8), 0);
    }

    #[test]
    fn physical_page_mapping_window_stays_inside_one_page() {
        assert_eq!(
            physical_page_mapping_window(0x1234_5008, 16),
            Some((0x1234_5000, 8, 24))
        );
        assert_eq!(
            physical_page_mapping_window(0x1234_5ff0, 16),
            Some((0x1234_5000, 0xff0, 0x1000))
        );
        assert_eq!(physical_page_mapping_window(0x1234_5ff1, 16), None);
        assert_eq!(physical_page_mapping_window(0x1234_5000, 0), None);
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
