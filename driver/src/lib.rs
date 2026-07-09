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
            diag,
            ept::{
                hooks::HookManager,
                paging::{AccessType, Ept},
            },
            vmm::Hypervisor,
        },
        utils::{
            alloc::PhysicalAllocator,
            nt::{init_kebugcheckex_sentinel, update_ntoskrnl_cr3},
        },
    },
    log::LevelFilter,
    wdk_sys::{
        DRIVER_UNLOAD, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, PVOID, STATUS_SUCCESS,
        UNICODE_STRING,
    },
};

pub mod expanded_stack;

static HYPERVISOR: AtomicPtr<Hypervisor> = AtomicPtr::new(null_mut());
const STAGE_STOP_STATUS_BASE: u32 = 0xE0F0_0000;
const BOOT_STOP_STAGE: u64 = parse_boot_stop_stage(option_env!("HV_BOOT_STOP_STAGE"));

fn hypervisor_initializing() -> *mut Hypervisor {
    usize::MAX as *mut Hypervisor
}

fn failed_entry_may_clear_hypervisor(current: *mut Hypervisor) -> bool {
    current == hypervisor_initializing()
}

const fn parse_boot_stop_stage(value: Option<&str>) -> u64 {
    let Some(value) = value else {
        return 0;
    };

    let bytes = value.as_bytes();
    let mut i = 0;
    let mut parsed = 0u64;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte < b'0' || byte > b'9' {
            return 0;
        }
        parsed = parsed * 10 + (byte - b'0') as u64;
        i += 1;
    }
    parsed
}

fn stage_stop_status(stage: u64) -> NTSTATUS {
    (STAGE_STOP_STATUS_BASE | (stage as u32 & 0xffff)) as NTSTATUS
}

fn boot_stage(stage: u64) -> Option<NTSTATUS> {
    diag::set_boot_stage(stage);
    log::info!("hv stage {}", stage);
    if BOOT_STOP_STAGE != 0 && stage >= BOOT_STOP_STAGE {
        log::info!("hv stop stage {}", stage);
        Some(stage_stop_status(stage))
    } else {
        None
    }
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
    hypervisor::intel::client_read::stop_worker();
    let hv = HYPERVISOR.swap(null_mut(), Ordering::AcqRel);
    if !hv.is_null() && hv != hypervisor_initializing() {
        let mut hv_box = Box::from_raw(hv);
        if let Err(error) = hv_box.devirtualize_system() {
            log::error!("Failed to devirtualize during unload: {}", error);
            HYPERVISOR.store(Box::into_raw(hv_box), Ordering::Release);
            return;
        }
        drop(hv_box);
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
        HypervisorError::BootStageStop => 0x34,
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
    if let Some(status) = boot_stage(100) {
        return status;
    }

    if !driver_object.is_null() {
        register_driver_unload(driver_object);
        if let Some(status) = boot_stage(110) {
            return status;
        }
    }

    with_expanded_stack(|| virtualize_system())
}

fn virtualize_system() -> NTSTATUS {
    if let Some(status) = boot_stage(120) {
        return status;
    }
    if HYPERVISOR
        .compare_exchange(
            null_mut(),
            hypervisor_initializing(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        let _ = boot_stage(121);
        return STATUS_SUCCESS;
    }

    if let Some(status) = boot_stage(130) {
        HYPERVISOR.store(null_mut(), Ordering::Release);
        return status;
    }
    let status = virtualize_system_claimed();
    if status != STATUS_SUCCESS {
        let _ = boot_stage(131);
        if failed_entry_may_clear_hypervisor(HYPERVISOR.load(Ordering::Acquire)) {
            let _ = HYPERVISOR.compare_exchange(
                hypervisor_initializing(),
                null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    status
}

fn virtualize_system_claimed() -> NTSTATUS {
    if let Some(status) = boot_stage(200) {
        return status;
    }
    let primary_ept: Box<Ept, PhysicalAllocator> = match Box::try_new_zeroed_in(PhysicalAllocator) {
        Ok(b) => unsafe { b.assume_init() },
        Err(_) => {
            let _ = boot_stage(201);
            return 0xE0020000u32 as NTSTATUS;
        }
    };

    let mut primary_ept = primary_ept;
    if let Some(status) = boot_stage(210) {
        return status;
    }
    if primary_ept
        .identity_2mb(AccessType::READ_WRITE_EXECUTE)
        .is_err()
    {
        let _ = boot_stage(211);
        return 0xE0030000u32 as NTSTATUS;
    }

    if let Some(status) = boot_stage(220) {
        return status;
    }
    let hook_manager = HookManager::new(vec![]);
    let mut hv = match Hypervisor::builder()
        .primary_ept(primary_ept)
        .hook_manager(hook_manager)
        .build()
    {
        Ok(h) => h,
        Err(e) => {
            let _ = boot_stage(221);
            return hv_err_to_code(0xE0040000, e);
        }
    };

    if let Some(status) = boot_stage(230) {
        return status;
    }
    update_ntoskrnl_cr3();
    init_kebugcheckex_sentinel();

    if let Some(status) = boot_stage(240) {
        return status;
    }
    match hv.virtualize_core() {
        Ok(_) => {
            let _ = boot_stage(250);
        }
        Err(e) => {
            let _ = boot_stage(241);
            let status = hv_err_to_code(0xE0050000, e);
            if let Err(error) = hv.devirtualize_system() {
                log::error!(
                    "Failed to cleanup after partial virtualization failure: {}",
                    error
                );
                let hv = Box::new(hv);
                HYPERVISOR.store(Box::into_raw(hv), Ordering::Release);
            }
            return status;
        }
    }

    if !hypervisor::intel::client_read::start_worker_if_enabled() {
        log::error!("Failed to start client read worker");
        if let Err(error) = hv.devirtualize_system() {
            log::error!(
                "Failed to cleanup after client read worker failure: {}",
                error
            );
            let hv = Box::new(hv);
            HYPERVISOR.store(Box::into_raw(hv), Ordering::Release);
        }
        return 0xE0053600u32 as NTSTATUS;
    }

    let hv = Box::new(hv);
    HYPERVISOR.store(Box::into_raw(hv), Ordering::Release);
    let _ = boot_stage(260);
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_entry_only_clears_initializing_sentinel() {
        assert!(failed_entry_may_clear_hypervisor(hypervisor_initializing()));
        assert!(!failed_entry_may_clear_hypervisor(null_mut()));
        assert!(!failed_entry_may_clear_hypervisor(
            0x1000usize as *mut Hypervisor
        ));
    }

    #[test]
    fn boot_stop_stage_parser_accepts_decimal_only() {
        assert_eq!(parse_boot_stop_stage(None), 0);
        assert_eq!(parse_boot_stop_stage(Some("")), 0);
        assert_eq!(parse_boot_stop_stage(Some("230")), 230);
        assert_eq!(parse_boot_stop_stage(Some("23x")), 0);
    }

    #[test]
    fn stage_stop_status_keeps_low_stage_bits() {
        assert_eq!(stage_stop_status(240) as u32, STAGE_STOP_STATUS_BASE | 240);
    }
}
