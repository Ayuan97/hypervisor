//! This crate provides an interface to a hypervisor.

#![no_std]
#![feature(allocator_api)]
#![feature(const_trait_impl)]
#![feature(once_cell_try)]

extern crate alloc;
extern crate static_assertions;

pub mod error;
pub mod intel;
pub mod utils;

#[cfg(test)]
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn test_driver_entry(
    _driver: *mut core::ffi::c_void,
    _registry_path: *mut core::ffi::c_void,
) -> i32 {
    0
}
