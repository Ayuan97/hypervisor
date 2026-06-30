#![no_std]
#![allow(unused_mut)]
#![feature(allocator_api)]

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL: hypervisor::utils::alloc::KernelAlloc = hypervisor::utils::alloc::KernelAlloc;

use {
    crate::expanded_stack::with_expanded_stack,
    alloc::{boxed::Box, vec},
    core::{
        ptr::null_mut,
        sync::atomic::{AtomicPtr, Ordering},
    },
    hypervisor::{
        error::HypervisorError,
        intel::{
            ept::{
                hooks::HookManager,
                paging::{AccessType, Ept},
            },
            vmm::Hypervisor,
        },
        utils::{alloc::PhysicalAllocator, nt::update_ntoskrnl_cr3},
    },
    log::LevelFilter,
    wdk_sys::{
        DRIVER_UNLOAD, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, PVOID, STATUS_SUCCESS,
        UNICODE_STRING,
    },
};

pub mod expanded_stack;

static HYPERVISOR: AtomicPtr<Hypervisor> = AtomicPtr::new(null_mut());

fn hypervisor_initializing() -> *mut Hypervisor {
    usize::MAX as *mut Hypervisor
}

#[repr(C)]
#[allow(dead_code)]
struct DriverObjectLayout {
    type_: i16,
    size: i16,
    device_object: PVOID,
    flags: u32,
    driver_start: PVOID,
    driver_size: u32,
    driver_section: PVOID,
    driver_extension: PVOID,
    driver_name: UNICODE_STRING,
    hardware_database: *mut UNICODE_STRING,
    fast_io_dispatch: PVOID,
    driver_init: PVOID,
    driver_start_io: PVOID,
    driver_unload: DRIVER_UNLOAD,
    major_function: [PVOID; 28],
}

const _: () = assert!(core::mem::size_of::<DriverObjectLayout>() == 336);
const _: () = assert!(core::mem::align_of::<DriverObjectLayout>() == 8);
const _: () = assert!(core::mem::offset_of!(DriverObjectLayout, driver_unload) == 104);

unsafe fn register_driver_unload(driver_object: PDRIVER_OBJECT) {
    let driver = driver_object as *mut DriverObjectLayout;
    (*driver).driver_unload = Some(driver_unload);
}

unsafe extern "C" fn driver_unload(_driver_object: PDRIVER_OBJECT) {
    let hv = HYPERVISOR.swap(null_mut(), Ordering::AcqRel);
    if !hv.is_null() && hv != hypervisor_initializing() {
        drop(Box::from_raw(hv));
    }
}

// Stage error codes (read from kdmapper "DriverEntry returned 0x..."):
//   0xE0020000 = EPT allocation failed
//   0xE0030000 = identity_2mb failed
//   0xE004xx00 = Hypervisor::build failed, xx = sub-error:
//     01=CPUUnsupported 02=VMXUnsupported 03=MTRRUnsupported 04=VMXBIOSLock
//     10=MemoryAllocationFailed 11=VirtualToPhysicalAddr
//     20=MemoryTypeResolution 21=InvalidEptPml4Base
//     FF=other
//   0xE005xx00 = virtualize_core failed, xx = sub-error:
//     01=ProcessorSwitch 02=VMXONFailed 03=VMCLEARFailed
//     04=VMPTRLDFailed 05=VMWRITEFailed 06=VMLAUNCHFailed
//     FF=other
//   0x00000000 = OK

fn hv_err_to_code(base: u32, e: HypervisorError) -> NTSTATUS {
    let sub: u32 = match e {
        HypervisorError::CPUUnsupported => 0x01,
        HypervisorError::VMXUnsupported => 0x02,
        HypervisorError::MTRRUnsupported => 0x03,
        HypervisorError::VMXBIOSLock => 0x04,
        HypervisorError::MemoryAllocationFailed(_) => 0x05,
        HypervisorError::VirtualToPhysicalAddressFailed => 0x06,
        HypervisorError::VMXONFailed => 0x07,
        HypervisorError::VMXOFFFailed => 0x08,
        HypervisorError::VMCLEARFailed => 0x09,
        HypervisorError::VMPTRLDFailed => 0x0A,
        HypervisorError::VMREADFailed => 0x0B,
        HypervisorError::VMWRITEFailed => 0x0C,
        HypervisorError::VMLAUNCHFailed => 0x0D,
        HypervisorError::VMRESUMEFailed => 0x0E,
        HypervisorError::ProcessorSwitchFailed => 0x0F,
        HypervisorError::VcpuIsNone => 0x10,
        HypervisorError::UnknownVMExitReason => 0x11,
        HypervisorError::UnknownVMInstructionError => 0x12,
        HypervisorError::VmFailInvalid => 0x13,
        HypervisorError::UnhandledVmExit => 0x14,
        HypervisorError::KeRaiseIrqlToDpcLevelNull => 0x15,
        HypervisorError::InvalidEptPml4BaseAddress => 0x16,
        HypervisorError::MemoryTypeResolutionError => 0x17,
        HypervisorError::InvalidCr3BaseAddress => 0x18,
        HypervisorError::InvalidBytes => 0x19,
        HypervisorError::NotEnoughBytes => 0x1A,
        HypervisorError::NoInstructions => 0x1B,
        HypervisorError::EncodingFailed => 0x1C,
        HypervisorError::RelativeInstruction => 0x1D,
        HypervisorError::UnsupportedInstruction => 0x1E,
        HypervisorError::VmxNotInitialized => 0x1F,
        HypervisorError::HookError => 0x20,
        HypervisorError::PrimaryEPTNotProvided => 0x21,
        HypervisorError::SecondaryEPTNotProvided => 0x22,
        HypervisorError::InvalidPml4Entry => 0x23,
        HypervisorError::InvalidPdptEntry => 0x24,
        HypervisorError::InvalidPdEntry => 0x25,
        HypervisorError::InvalidPml1Entry => 0x26,
        HypervisorError::InvalidPermissionCharacter => 0x27,
        HypervisorError::UnalignedAddressError => 0x28,
        HypervisorError::AlreadySplitError => 0x29,
        HypervisorError::OutOfMemory => 0x2A,
        HypervisorError::PageAlreadySplit => 0x2B,
        HypervisorError::HookManagerNotProvided => 0x2C,
        HypervisorError::NtQuerySystemInformationFailed => 0x2D,
        HypervisorError::ExAllocatePoolFailed => 0x2E,
        HypervisorError::PatternNotFound => 0x2F,
        HypervisorError::SsdtNotFound => 0x30,
        HypervisorError::FailedToCreateCString(_) => 0x31,
        HypervisorError::GetKernelBaseFailed => 0x32,
        HypervisorError::HexParseError => 0x33,
    };
    (base | (sub << 8)) as NTSTATUS
}

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver_object: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    com_logger::builder()
        .base(0x2f8)
        .filter(LevelFilter::Info)
        .setup();

    if !driver_object.is_null() {
        register_driver_unload(driver_object);
    }

    with_expanded_stack(|| virtualize_system())
}

fn virtualize_system() -> NTSTATUS {
    if HYPERVISOR
        .compare_exchange(
            null_mut(),
            hypervisor_initializing(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return STATUS_SUCCESS;
    }

    let status = virtualize_system_claimed();
    if status != STATUS_SUCCESS {
        HYPERVISOR.store(null_mut(), Ordering::Release);
    }

    status
}

fn virtualize_system_claimed() -> NTSTATUS {
    let primary_ept: Box<Ept, PhysicalAllocator> = match Box::try_new_zeroed_in(PhysicalAllocator) {
        Ok(b) => unsafe { b.assume_init() },
        Err(_) => return 0xE0020000u32 as NTSTATUS,
    };

    let mut primary_ept = primary_ept;
    if primary_ept
        .identity_2mb(AccessType::READ_WRITE_EXECUTE)
        .is_err()
    {
        return 0xE0030000u32 as NTSTATUS;
    }

    let hook_manager = HookManager::new(vec![]);
    let mut hv = match Hypervisor::builder()
        .primary_ept(primary_ept)
        .hook_manager(hook_manager)
        .build()
    {
        Ok(h) => h,
        Err(e) => return hv_err_to_code(0xE0040000, e),
    };

    update_ntoskrnl_cr3();

    match hv.virtualize_core() {
        Ok(_) => {}
        Err(e) => return hv_err_to_code(0xE0050000, e),
    }

    let hv = Box::new(hv);
    HYPERVISOR.store(Box::into_raw(hv), Ordering::Release);
    STATUS_SUCCESS
}
