#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use {
    crate::error::HypervisorError,
    alloc::vec::Vec,
    core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicBool, Ordering},
    },
    wdk_sys::{
        ntddk::{
            KeDeregisterBugCheckCallback, KeLowerIrql, KeRegisterBugCheckCallback,
            KeStackAttachProcess, KeUnstackDetachProcess, MmGetSystemRoutineAddress,
        },
        _KAPC_STATE, _KBUGCHECK_CALLBACK_RECORD, _LIST_ENTRY, KIRQL, PEPROCESS, PKBUGCHECK_CALLBACK_RECORD,
        PRKPROCESS, PUCHAR, PVOID, UNICODE_STRING, ULONG,
    },
};

/// Gets a pointer to a function from ntoskrnl.exe exports.
///
/// # Arguments
/// * `function_name` - The name of the function to retrieve.
///
/// # Returns
/// A pointer to the requested function, or null if not found.
pub fn get_ntoskrnl_export(function_name: &str) -> PVOID {
    let wide_string: Vec<u16> = function_name
        .encode_utf16()
        .chain(core::iter::once(0)) // Add null terminator
        .collect();

    let unicode_string = UNICODE_STRING {
        Length: ((wide_string.len() - 1) * 2) as u16, // Length in bytes, excluding the null terminator
        MaximumLength: (wide_string.len() * 2) as u16,
        Buffer: wide_string.as_ptr() as *mut _,
    };

    // Using a local variable to hold the wide string ensures it is not dropped prematurely.
    let routine_address =
        unsafe { MmGetSystemRoutineAddress(&unicode_string as *const _ as *mut _) };

    // The wide_string will be dropped here, after the UNICODE_STRING is no longer needed.
    routine_address
}

/// Raises the current IRQL to DISPATCH_LEVEL and returns the previous IRQL.
///
/// # Returns
/// * `Ok(KIRQL)` with the previous IRQL on success, or `Err(HypervisorError::KeRaiseIrqlToDpcLevelNull)` if the function pointer is null.
pub fn raise_irql_to_dpc_level() -> Result<KIRQL, HypervisorError> {
    type FnKeRaiseIrqlToDpcLevel = unsafe extern "system" fn() -> KIRQL;

    // Get the address of the function from ntoskrnl
    let routine_address = get_ntoskrnl_export("KeRaiseIrqlToDpcLevel");

    // Ensure that the address is valid
    let pKeRaiseIrqlToDpcLevel = if !routine_address.is_null() {
        unsafe { core::mem::transmute::<PVOID, FnKeRaiseIrqlToDpcLevel>(routine_address) }
    } else {
        return Err(HypervisorError::KeRaiseIrqlToDpcLevelNull);
    };

    // Invoke the retrieved function
    Ok(unsafe { pKeRaiseIrqlToDpcLevel() })
}

/// Lowers the current IRQL to the specified value.
///
/// # Arguments
/// * `old_irql` - The IRQL to which the current IRQL should be lowered.
pub fn lower_irql_to_old_level(old_irql: KIRQL) {
    // Directly manipulating the IRQL is an unsafe operation
    unsafe { KeLowerIrql(old_irql) };
}

/// Represents the CR3 (Directory Table Base) of the system process.
///
/// This is typically used to store the page table root physical address
/// of the system process for use in virtual-to-physical address translation.
pub static mut NTOSKRNL_CR3: u64 = 0;

/// Physical address of the identity-mapped PML4, for temporary CR3 switching
/// in VMX root mode when accessing arbitrary physical memory.
pub static mut IDENTITY_CR3: u64 = 0;

/// Updates the `NTOSKRNL_CR3` static with the CR3 of the system process.
///
/// Retrieves the Directory Table Base (DirBase) of the system process,
/// typically corresponding to the NT kernel (`ntoskrnl`).
///
/// # Credits
///
/// Credits to @Drew from https://github.com/drew-gpf for the help.
pub fn update_ntoskrnl_cr3() {
    // Default initialization of APC state.
    let mut apc_state = _KAPC_STATE::default();

    // Attach to the system process's stack safely.
    // `KeStackAttachProcess` is unsafe as it manipulates thread execution context.
    unsafe { KeStackAttachProcess(PsInitialSystemProcess as PRKPROCESS, &mut apc_state) };

    // Update the NTOSKRNL_CR3 static with the current CR3 value.
    // Accessing CR3 is an unsafe operation as it involves reading a control register.
    unsafe {
        NTOSKRNL_CR3 = x86::controlregs::cr3();
    }

    log::trace!("NTOSKRNL_CR3: {:#x}", unsafe { NTOSKRNL_CR3 });

    // Detach from the system process's stack safely.
    // `KeUnstackDetachProcess` is unsafe as it restores the previous thread execution context.
    unsafe { KeUnstackDetachProcess(&mut apc_state) };
}

/// Resolve `nt!KeBugCheckEx` and store its address + first 8 bytes into the
/// diagnostic sentinel. Called during driver init after `NTOSKRNL_CR3` is
/// available so the read is guaranteed to hit paged-in kernel memory. If EAC
/// triggers a bugcheck later, guest RIP inside VM-exits will hit this range;
/// see `diag::observe_guest_rip_for_bugcheck`.
pub fn init_kebugcheckex_sentinel() {
    let address = get_ntoskrnl_export("KeBugCheckEx");
    if address.is_null() {
        log::error!("KeBugCheckEx not resolved");
        return;
    }
    let addr_u64 = address as usize as u64;
    let first_qword = unsafe { core::ptr::read_volatile(address as *const u64) };
    crate::intel::diag::set_kebugcheckex_sentinel(addr_u64, first_qword);
    log::info!(
        "KeBugCheckEx sentinel: addr={:#x} bytes={:#x}",
        addr_u64,
        first_qword
    );
}

/// Non-paged storage for the bug-check callback record. `KeRegisterBugCheckCallback`
/// requires this to live in resident memory, so a static is the correct fit —
/// the driver's data section is never paged out. Access is single-threaded
/// (only from DriverEntry / driver_unload) so `UnsafeCell` is enough.
#[repr(C)]
struct BugCheckCallbackCell(UnsafeCell<_KBUGCHECK_CALLBACK_RECORD>);
unsafe impl Sync for BugCheckCallbackCell {}

static BUGCHECK_CALLBACK_RECORD: BugCheckCallbackCell = BugCheckCallbackCell(UnsafeCell::new(
    _KBUGCHECK_CALLBACK_RECORD {
        Entry: _LIST_ENTRY {
            Flink: core::ptr::null_mut(),
            Blink: core::ptr::null_mut(),
        },
        CallbackRoutine: None,
        Buffer: core::ptr::null_mut(),
        Length: 0,
        Component: core::ptr::null_mut(),
        Checksum: 0,
        State: 0,
    },
));

static BUGCHECK_CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Component name shown by the `!bugdump` debugger extension. Static byte slice
/// with a trailing NUL so the pointer is stable and null-terminated as required
/// by Windows.
const BUGCHECK_COMPONENT: &[u8] = b"matrix\0";

/// Called by Windows when the system enters bug-check processing. IRQL is
/// HIGH_LEVEL, other CPUs are already suspended, so we cannot devirtualise the
/// whole system from here. The value is diagnostic: mark that a bug check
/// actually reached callback dispatch and stash a CMOS breadcrumb that
/// survives the hard reboot users typically do after a freeze.
///
/// Per Task 3 subagent analysis: this callback fires too late to save the
/// system — the "止血带" (bandaid) role is all we get. If future EAC variants
/// re-trigger bug checks it at least tells us the path executed.
unsafe extern "C" fn bugcheck_callback(_buffer: PVOID, _length: ULONG) {
    crate::intel::diag::note_bugcheck_callback_fired();
}

/// Register the bug-check callback. Idempotent — calling twice is a no-op.
/// Must be called after the hypervisor is up so that `KeRegisterBugCheckCallback`
/// itself (which lives in ntoskrnl.exe) is reachable through the guest CR3.
pub fn register_bugcheck_callback() {
    if BUGCHECK_CALLBACK_REGISTERED.load(Ordering::Acquire) {
        return;
    }
    let record = BUGCHECK_CALLBACK_RECORD.0.get();
    unsafe {
        (*record).CallbackRoutine = Some(bugcheck_callback);
        (*record).Buffer = core::ptr::null_mut();
        (*record).Length = 0;
        (*record).Component = BUGCHECK_COMPONENT.as_ptr() as PUCHAR;
        (*record).State = 0;
    }
    let ok = unsafe {
        KeRegisterBugCheckCallback(
            record as PKBUGCHECK_CALLBACK_RECORD,
            Some(bugcheck_callback),
            core::ptr::null_mut(),
            0,
            BUGCHECK_COMPONENT.as_ptr() as PUCHAR,
        )
    };
    if ok != 0 {
        BUGCHECK_CALLBACK_REGISTERED.store(true, Ordering::Release);
        log::info!("KeRegisterBugCheckCallback OK");
    } else {
        log::error!("KeRegisterBugCheckCallback failed");
    }
}

/// Deregister the bug-check callback. Must run before driver unload —
/// leaving a stale callback in the kernel list would fire into freed memory.
///
/// Returns true iff the callback was successfully deregistered (or was not
/// registered in the first place). A false return means the kernel refused
/// deregistration and the callback record is still linked in — proceeding
/// with driver unload in that state is dangerous.
pub fn deregister_bugcheck_callback() -> bool {
    if !BUGCHECK_CALLBACK_REGISTERED.load(Ordering::Acquire) {
        return true;
    }
    let record = BUGCHECK_CALLBACK_RECORD.0.get();
    let ok = unsafe { KeDeregisterBugCheckCallback(record as PKBUGCHECK_CALLBACK_RECORD) };
    if ok != 0 {
        BUGCHECK_CALLBACK_REGISTERED.store(false, Ordering::Release);
        true
    } else {
        // Keep REGISTERED=true so any subsequent unload attempts try again
        // rather than assuming the record is safely unlinked.
        log::error!(
            "KeDeregisterBugCheckCallback failed; bug-check record still linked into kernel list"
        );
        false
    }
}

#[link(name = "ntoskrnl")]
extern "C" {
    pub static mut PsInitialSystemProcess: PEPROCESS;
}

#[link(name = "ntoskrnl")]
extern "system" {
    /// The RtlCopyMemory routine copies the contents of a source memory block to a destination memory block.
    /// Callers of RtlCopyMemory can be running at any IRQL if the source and destination memory blocks are in nonpaged system memory.
    /// Otherwise, the caller must be running at IRQL <= APC_LEVEL.
    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory
    pub fn RtlCopyMemory(destination: *mut u64, source: *mut u64, length: usize);
}
