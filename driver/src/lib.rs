#![no_std]

extern crate alloc;
extern crate wdk_panic;

use wdk_alloc::WdkAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

// DriverEntry: called when driver loads
// 1. Initialize logging (serial port COM1)
// 2. Check VMX/EPT support
// 3. Virtualize all logical processors
// 4. Return STATUS_SUCCESS
//
// DriverUnload: called when driver unloads
// 1. VMCALL(devirtualize) on each core
// 2. VMXOFF
// 3. Free VMXON/VMCS/EPT memory
//
// Reference: matrix-rs/driver/src/lib.rs
