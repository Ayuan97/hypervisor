#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use {
    crate::error::HypervisorError,
    alloc::vec::Vec,
    core::sync::atomic::AtomicU64,
    wdk_sys::{
        ntddk::{
            KeLowerIrql, KeStackAttachProcess, KeUnstackDetachProcess, MmGetSystemRoutineAddress,
        },
        _KAPC_STATE, KIRQL, PEPROCESS, PRKPROCESS, PVOID, UNICODE_STRING,
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

/// Physical address of the HV-owned identity-mapped PML4 used as **VMCS HOST_CR3**.
///
/// Built in `HypervisorBuilder::build` before any VMLAUNCH. Must not be confused
/// with `NTOSKRNL_CR3` (System process DTB): EAC CR3-trashing overwrites System
/// tables and then forces a VMEXIT; if HOST_CR3 still points at those pages the
/// host freezes (UC 593430). See `docs/eac-isolation-audit.md`.
pub static IDENTITY_CR3: AtomicU64 = AtomicU64::new(0);

/// CR3 value for `VMCS.HOST_CR3`: private identity map only.
///
/// Fail-closed if `IDENTITY_CR3` is still zero (build order bug). Never falls
/// back to `NTOSKRNL_CR3`.
pub fn host_cr3_for_vmcs() -> Result<u64, crate::error::HypervisorError> {
    let host_cr3 = IDENTITY_CR3.load(core::sync::atomic::Ordering::Acquire);
    if host_cr3 == 0 {
        return Err(crate::error::HypervisorError::InvalidCr3BaseAddress);
    }
    Ok(host_cr3)
}

#[cfg(test)]
mod host_cr3_tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn host_cr3_for_vmcs_rejects_zero_and_returns_identity() {
        let prev = IDENTITY_CR3.swap(0, Ordering::AcqRel);
        assert!(matches!(
            host_cr3_for_vmcs(),
            Err(crate::error::HypervisorError::InvalidCr3BaseAddress)
        ));
        // Any non-zero PA is accepted; alignment is enforced when the map is built.
        const SAMPLE_PA: u64 = 0x1_0000;
        IDENTITY_CR3.store(SAMPLE_PA, Ordering::Release);
        assert_eq!(host_cr3_for_vmcs().expect("identity set"), SAMPLE_PA);
        IDENTITY_CR3.store(prev, Ordering::Release);
    }
}

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

/// Never register `KeRegisterBugCheckCallback` — a list entry with component
/// string is an instant HV signature. Bugcheck evidence uses the RIP sentinel.
pub fn register_bugcheck_callback() {
    log::info!("KeRegisterBugCheckCallback skipped (permanently disabled for stealth)");
}

/// Always succeeds: we never register a callback, so there is nothing to
/// unlink on unload.
pub fn deregister_bugcheck_callback() -> bool {
    true
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


