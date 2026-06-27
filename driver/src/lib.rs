#![no_std]
#![allow(unused_mut)]
#![feature(allocator_api, new_uninit)]
#![feature(link_llvm_intrinsics)]

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL: hypervisor::utils::alloc::KernelAlloc = hypervisor::utils::alloc::KernelAlloc;

use {
    crate::expanded_stack::with_expanded_stack,
    alloc::{boxed::Box, vec},
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
    wdk_sys::{DRIVER_OBJECT, NTSTATUS, PUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
};

pub mod expanded_stack;

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    com_logger::builder()
        .base(0x2f8)
        .filter(LevelFilter::Info)
        .setup();

    log::info!("Hypervisor driver loading...");

    // wdk-sys 0.2.0 generates DRIVER_OBJECT as opaque; set DriverUnload at offset 0x68 (x64)
    let unload_ptr = (driver as *mut DRIVER_OBJECT as *mut u8).add(0x68)
        as *mut Option<unsafe extern "C" fn(*mut DRIVER_OBJECT)>;
    *unload_ptr = Some(driver_unload);

    with_expanded_stack(|| {
        match virtualize_system() {
            Ok(_) => log::info!("System virtualized successfully"),
            Err(err) => {
                log::error!("Virtualization failed: {:?}", err);
                return STATUS_UNSUCCESSFUL;
            }
        }
        STATUS_SUCCESS
    })
}

pub extern "C" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    log::info!("Hypervisor driver unloading...");
    if let Some(hypervisor) = unsafe { HYPERVISOR.take() } {
        drop(hypervisor);
    }
}

static mut HYPERVISOR: Option<Hypervisor> = None;

fn virtualize_system() -> Result<(), HypervisorError> {
    let mut primary_ept: Box<Ept, PhysicalAllocator> =
        unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

    log::info!("Creating primary EPT (identity map)");
    primary_ept.identity_2mb(AccessType::READ_WRITE_EXECUTE)?;

    let hook_manager = HookManager::new(vec![]);

    let mut hv = Hypervisor::builder()
        .primary_ept(primary_ept)
        .hook_manager(hook_manager)
        .build()?;

    update_ntoskrnl_cr3();

    hv.virtualize_core()?;
    log::info!("All cores virtualized, VMCALL interface ready");

    unsafe { HYPERVISOR = Some(hv) };

    Ok(())
}
