//! A module for managing Intel VMX-based virtualization.
//!
//! This module provides structures and functions for interacting with Intel's VMX
//! virtualization extensions. It offers abstractions for the guest's register state,
//! VM-entry, VM-exit, and handling VMX-specific instructions.
//!
//! Credits to Satoshi, Daax, and Drew for their valuable contributions and code snippets.
//! Satoshi's Hypervisor-101 in Rust: https://github.com/tandasat/Hypervisor-101-in-Rust/blob/main/hypervisor/src/hardware_vt/vmx_run_vm.S
//! Daax: https://github.com/daaximus
//! Drew: https://github.com/drew-gpf

use crate::{
    intel::{
        events::EventInjection,
        support::{vmread_checked, vmxoff},
        vcpu::Vcpu,
        vmerror::VmInstructionError,
        vmexit::{GuestRootState, VmExit},
        vmx::Vmx,
    },
    utils::{capture::GuestRegisters, processor::clear_virtualized},
};

extern "C" {
    /// Launches the VM using VMX instructions.
    ///
    /// This function is defined in Assembly and interacts directly with the VMX
    /// instructions `vmlaunch` and `vmresume`. Upon successful execution, this function
    /// does not return, instead transitioning control to the guest VM. On VM-exit,
    /// the function returns, allowing the hypervisor to handle the exit.
    ///
    /// # Arguments
    ///
    /// * `general_purpose_registers` - A pointer to the `GuestRegisters` structure
    /// * `host_rsp` - A pointer to the end of `stack_contents` in the `VmStack` structure.
    pub fn launch_vm(guest_registers: &mut GuestRegisters, host_rsp: *mut u64);

    /// Assembly stub for handling VM exits.
    pub fn vmexit_stub();
}

core::arch::global_asm!(
    r#"
.set registers_rax, 0x0
.set registers_rbx, 0x8
.set registers_rcx, 0x10
.set registers_rdx, 0x18
.set registers_rdi, 0x20
.set registers_rsi, 0x28
.set registers_rbp, 0x30
.set registers_r8,  0x38
.set registers_r9,  0x40
.set registers_r10, 0x48
.set registers_r11, 0x50
.set registers_r12, 0x58
.set registers_r13, 0x60
.set registers_r14, 0x68
.set registers_r15, 0x70
.set registers_rip, 0x78
.set registers_rsp, 0x80
.set registers_rflags, 0x88
.set registers_xmm0, 0x90
.set registers_xmm1, 0xA0
.set registers_xmm2, 0xB0
.set registers_xmm3, 0xC0
.set registers_xmm4, 0xD0
.set registers_xmm5, 0xE0
.set registers_xmm6, 0xF0
.set registers_xmm7, 0x100
.set registers_xmm8, 0x110
.set registers_xmm9, 0x120
.set registers_xmm10, 0x130
.set registers_xmm11, 0x140
.set registers_xmm12, 0x150
.set registers_xmm13, 0x160
.set registers_xmm14, 0x170
.set registers_xmm15, 0x180
.set vmstack_original_rsp, 0x8
.set vmstack_host_xmm6, 0x10
.set vmstack_host_xmm7, 0x20
.set vmstack_host_xmm8, 0x30
.set vmstack_host_xmm9, 0x40
.set vmstack_host_xmm10, 0x50
.set vmstack_host_xmm11, 0x60
.set vmstack_host_xmm12, 0x70
.set vmstack_host_xmm13, 0x80
.set vmstack_host_xmm14, 0x90
.set vmstack_host_xmm15, 0xA0
.set launch_saved_r15, 0x08
.set launch_saved_r14, 0x10
.set launch_saved_r13, 0x18
.set launch_saved_r12, 0x20
.set launch_saved_rdi, 0x48
.set launch_saved_rsi, 0x50
.set launch_saved_rbp, 0x58
.set launch_saved_rbx, 0x60
.set launch_vmstack_vmx, 0x80
.set launch_original_rsp, 0x88
.set launch_host_xmm6, 0x90
.set launch_host_xmm7, 0xA0
.set launch_host_xmm8, 0xB0
.set launch_host_xmm9, 0xC0
.set launch_host_xmm10, 0xD0
.set launch_host_xmm11, 0xE0
.set launch_host_xmm12, 0xF0
.set launch_host_xmm13, 0x100
.set launch_host_xmm14, 0x110
.set launch_host_xmm15, 0x120

.global launch_vm
launch_vm:
    // Save the original host stack and Windows x64 nonvolatile XMM registers
    // in the VmStack footer before switching RSP.
    mov     [rdx + vmstack_original_rsp], rsp
    movdqa  [rdx + vmstack_host_xmm6], xmm6
    movdqa  [rdx + vmstack_host_xmm7], xmm7
    movdqa  [rdx + vmstack_host_xmm8], xmm8
    movdqa  [rdx + vmstack_host_xmm9], xmm9
    movdqa  [rdx + vmstack_host_xmm10], xmm10
    movdqa  [rdx + vmstack_host_xmm11], xmm11
    movdqa  [rdx + vmstack_host_xmm12], xmm12
    movdqa  [rdx + vmstack_host_xmm13], xmm13
    movdqa  [rdx + vmstack_host_xmm14], xmm14
    movdqa  [rdx + vmstack_host_xmm15], xmm15

    // Set host stack pointer (RSP) to the end of stack_contents in VmStack.
    mov rsp, rdx

    // Push host general-purpose registers onto the stack.
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    // Load pointer to guest's register state into r15.
    mov     r15, rcx

    // Store the pointer to guest registers onto the stack.
    push    rcx

    // Restore guest registers from the provided state.
    mov     rax, [r15 + registers_rax]
    mov     rbx, [r15 + registers_rbx]
    mov     rcx, [r15 + registers_rcx]
    mov     rdx, [r15 + registers_rdx]
    mov     rdi, [r15 + registers_rdi]
    mov     rsi, [r15 + registers_rsi]
    mov     rbp, [r15 + registers_rbp]
    mov      r8, [r15 + registers_r8]
    mov      r9, [r15 + registers_r9]
    mov     r10, [r15 + registers_r10]
    mov     r11, [r15 + registers_r11]
    mov     r12, [r15 + registers_r12]

    // Restore guest XMM registers.
    movdqa  xmm0, [r15 + registers_xmm0]
    movdqa  xmm1, [r15 + registers_xmm1]
    movdqa  xmm2, [r15 + registers_xmm2]
    movdqa  xmm3, [r15 + registers_xmm3]
    movdqa  xmm4, [r15 + registers_xmm4]
    movdqa  xmm5, [r15 + registers_xmm5]
    movdqa  xmm6, [r15 + registers_xmm6]
    movdqa  xmm7, [r15 + registers_xmm7]
    movdqa  xmm8, [r15 + registers_xmm8]
    movdqa  xmm9, [r15 + registers_xmm9]
    movdqa  xmm10, [r15 + registers_xmm10]
    movdqa  xmm11, [r15 + registers_xmm11]
    movdqa  xmm12, [r15 + registers_xmm12]
    movdqa  xmm13, [r15 + registers_xmm13]
    movdqa  xmm14, [r15 + registers_xmm14]
    movdqa  xmm15, [r15 + registers_xmm15]

    // Prepare VMCS for VM launch: set HOST_RSP and HOST_RIP.
    mov     r14, 0x6C14 // VMCS_HOST_RSP
    vmwrite r14, rsp
    lea     r13, [rip + vmexit_stub]
    mov     r14, 0x6C16 // VMCS_HOST_RIP
    vmwrite r14, r13

    // Restore additional guest registers.
    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]
    mov     r15, [r15 + registers_r15]

    // Launch the VM.
    vmlaunch

    sub     rsp, 0x20
    call x1
    add     rsp, 0x20

    movdqa  xmm6, [rsp + launch_host_xmm6]
    movdqa  xmm7, [rsp + launch_host_xmm7]
    movdqa  xmm8, [rsp + launch_host_xmm8]
    movdqa  xmm9, [rsp + launch_host_xmm9]
    movdqa  xmm10, [rsp + launch_host_xmm10]
    movdqa  xmm11, [rsp + launch_host_xmm11]
    movdqa  xmm12, [rsp + launch_host_xmm12]
    movdqa  xmm13, [rsp + launch_host_xmm13]
    movdqa  xmm14, [rsp + launch_host_xmm14]
    movdqa  xmm15, [rsp + launch_host_xmm15]

    mov     rbx, [rsp + launch_saved_rbx]
    mov     rbp, [rsp + launch_saved_rbp]
    mov     rsi, [rsp + launch_saved_rsi]
    mov     rdi, [rsp + launch_saved_rdi]
    mov     r12, [rsp + launch_saved_r12]
    mov     r13, [rsp + launch_saved_r13]
    mov     r14, [rsp + launch_saved_r14]
    mov     r15, [rsp + launch_saved_r15]

    mov     rax, [rsp + launch_original_rsp]
    mov     rsp, rax
    ret

.global vmexit_stub
vmexit_stub:
    // Exchange the top of stack with r15 to get pointer to guest registers.
    xchg    r15, [rsp]

    // Save guest general-purpose registers to their respective locations.
    mov     [r15 + registers_rax], rax
    mov     [r15 + registers_rbx], rbx
    mov     [r15 + registers_rcx], rcx
    mov     [r15 + registers_rdx], rdx
    mov     [r15 + registers_rsi], rsi
    mov     [r15 + registers_rdi], rdi
    mov     [r15 + registers_rbp], rbp
    mov     [r15 + registers_r8],  r8
    mov     [r15 + registers_r9],  r9
    mov     [r15 + registers_r10], r10
    mov     [r15 + registers_r11], r11
    mov     [r15 + registers_r12], r12
    mov     [r15 + registers_r13], r13
    mov     [r15 + registers_r14], r14

    // Save guest XMM registers.
    movdqa  [r15 + registers_xmm0], xmm0
    movdqa  [r15 + registers_xmm1], xmm1
    movdqa  [r15 + registers_xmm2], xmm2
    movdqa  [r15 + registers_xmm3], xmm3
    movdqa  [r15 + registers_xmm4], xmm4
    movdqa  [r15 + registers_xmm5], xmm5
    movdqa  [r15 + registers_xmm6], xmm6
    movdqa  [r15 + registers_xmm7], xmm7
    movdqa  [r15 + registers_xmm8], xmm8
    movdqa  [r15 + registers_xmm9], xmm9
    movdqa  [r15 + registers_xmm10], xmm10
    movdqa  [r15 + registers_xmm11], xmm11
    movdqa  [r15 + registers_xmm12], xmm12
    movdqa  [r15 + registers_xmm13], xmm13
    movdqa  [r15 + registers_xmm14], xmm14
    movdqa  [r15 + registers_xmm15], xmm15

    // Set rcx to point to the saved guest registers for `vmexit_handler` (1st parameter).
    mov rcx, r15

    // Set rdx to point to the saved `Vmx` pointer for `vmexit_handler` (2nd parameter).
    // 8 (0x8) x 16 (0x10) = 128 (0x80) bytes away is `Vmx` pointer.
    mov rdx, [rsp + 0x80]

    // Temporarily save and restore r15, keeping guest registers pointer on stack.
    mov     rax, [rsp]
    xchg    r15, [rsp]
    mov     [rcx + registers_r15], rax

    // Allocate stack space for the VM exit handler.
    sub     rsp, 0x20

    // Call the VM exit handler.
    call x0

    // Restore stack pointer after VM exit handling.
    add rsp, 0x20

    // A non-zero return value means the handler already left VMX root
    // and the guest context should be restored without VMRESUME.
    test    rax, rax
    jne     vmexit_devirtualize_restore

    // Recovery entry point for host IDT fault handlers (#GP, NMI).
    // They set RSP = HOST_RSP and jump here.
.global vmexit_restore
vmexit_restore:
    // Retrieve pointer to guest registers for restoration.
    mov     r15, [rsp]

    // Restore guest registers for next VM entry.
    mov     rax, [r15 + registers_rax]
    mov     rbx, [r15 + registers_rbx]
    mov     rcx, [r15 + registers_rcx]
    mov     rdx, [r15 + registers_rdx]
    mov     rdi, [r15 + registers_rdi]
    mov     rsi, [r15 + registers_rsi]
    mov     rbp, [r15 + registers_rbp]
    mov      r8, [r15 + registers_r8]
    mov      r9, [r15 + registers_r9]
    mov     r10, [r15 + registers_r10]
    mov     r11, [r15 + registers_r11]
    mov     r12, [r15 + registers_r12]
    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]

    movdqa  xmm0, [r15 + registers_xmm0]
    movdqa  xmm1, [r15 + registers_xmm1]
    movdqa  xmm2, [r15 + registers_xmm2]
    movdqa  xmm3, [r15 + registers_xmm3]
    movdqa  xmm4, [r15 + registers_xmm4]
    movdqa  xmm5, [r15 + registers_xmm5]
    movdqa  xmm6, [r15 + registers_xmm6]
    movdqa  xmm7, [r15 + registers_xmm7]
    movdqa  xmm8, [r15 + registers_xmm8]
    movdqa  xmm9, [r15 + registers_xmm9]
    movdqa  xmm10, [r15 + registers_xmm10]
    movdqa  xmm11, [r15 + registers_xmm11]
    movdqa  xmm12, [r15 + registers_xmm12]
    movdqa  xmm13, [r15 + registers_xmm13]
    movdqa  xmm14, [r15 + registers_xmm14]
    movdqa  xmm15, [r15 + registers_xmm15]

    // Do this last to avoid overwriting r15.
    mov     r15, [r15 + registers_r15]

    // Attempt to resume the guest virtual machine.
    vmresume

    // If VMRESUME fails, handle the failure.
    mov     rcx, [rsp + 0x80]
    sub     rsp, 0x20
    call x2
    add     rsp, 0x20

vmexit_devirtualize_restore:
    // Retrieve pointer to guest registers for restoration.
    mov     r15, [rsp]

    // Build an iret-like tail on the guest stack: RFLAGS then RIP.
    mov     rax, [r15 + registers_rsp]
    sub     rax, 0x10
    mov     r11, [r15 + registers_rflags]
    mov     [rax], r11
    mov     r11, [r15 + registers_rip]
    mov     [rax + 0x8], r11
    mov     rsp, rax

    movdqa  xmm0, [r15 + registers_xmm0]
    movdqa  xmm1, [r15 + registers_xmm1]
    movdqa  xmm2, [r15 + registers_xmm2]
    movdqa  xmm3, [r15 + registers_xmm3]
    movdqa  xmm4, [r15 + registers_xmm4]
    movdqa  xmm5, [r15 + registers_xmm5]
    movdqa  xmm6, [r15 + registers_xmm6]
    movdqa  xmm7, [r15 + registers_xmm7]
    movdqa  xmm8, [r15 + registers_xmm8]
    movdqa  xmm9, [r15 + registers_xmm9]
    movdqa  xmm10, [r15 + registers_xmm10]
    movdqa  xmm11, [r15 + registers_xmm11]
    movdqa  xmm12, [r15 + registers_xmm12]
    movdqa  xmm13, [r15 + registers_xmm13]
    movdqa  xmm14, [r15 + registers_xmm14]
    movdqa  xmm15, [r15 + registers_xmm15]

    mov     rax, [r15 + registers_rax]
    mov     rbx, [r15 + registers_rbx]
    mov     rcx, [r15 + registers_rcx]
    mov     rdx, [r15 + registers_rdx]
    mov     rdi, [r15 + registers_rdi]
    mov     rsi, [r15 + registers_rsi]
    mov     rbp, [r15 + registers_rbp]
    mov      r8, [r15 + registers_r8]
    mov      r9, [r15 + registers_r9]
    mov     r10, [r15 + registers_r10]
    mov     r11, [r15 + registers_r11]
    mov     r12, [r15 + registers_r12]
    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]
    mov     r15, [r15 + registers_r15]

    popfq
    ret
"#
);

// Handles VM exits.
///
/// This function is called when a VM exit occurs, and is responsible for handling
/// the VM exit logic.
///
/// # Arguments
///
/// * `registers` - A pointer to `GuestRegisters` representing the guest's state at VM exit.
///
#[export_name = "x0"]
pub unsafe extern "C" fn vmexit_handler(registers: *mut GuestRegisters, vmx: *mut u64) -> u64 {
    if registers.is_null() {
        log::error!("vmexit_handler received a null pointer for registers");
        fatal_vmx_failure_loop();
    }
    if vmx.is_null() {
        log::error!("vmexit_handler received a null pointer for vmx");
        fatal_vmx_failure_loop();
    }

    let registers = &mut *registers;
    let vmx = &mut *(vmx as *mut Vmx);
    let vmexit = VmExit::new();

    match vmexit.handle_vmexit(registers, vmx) {
        Ok(crate::intel::vmexit::ExitType::ExitHypervisor) => 1,
        Ok(_) => 0,
        Err(e) => {
            log::error!("Failed to handle VMEXIT: {:?}", e);
            EventInjection::vmentry_inject_ud();
            0
        }
    }
}

/// Handles the failure of the `VMLAUNCH` instruction.
///
/// This function is invoked when `VMLAUNCH` fails, and it retrieves and reports
/// the specific VM instruction error.
///
/// Note: This can be handled with IDT later instead.
#[export_name = "x1"]
pub extern "C" fn vmlaunch_failed() {
    log_vm_instruction_failure("VMLAUNCH");
    if let Err(error) = vmxoff() {
        log::error!(
            "Failed to leave VMX operation after VMLAUNCH failure: {:?}",
            error
        );
        fatal_vmx_failure_loop();
    }
}

/// Handles the failure of the `VMRESUME` instruction.
///
/// This function is invoked when `VMRESUME` fails, retrieving and reporting
/// the specific VM instruction error.
///
/// Note: This can be handled with IDT later instead.
#[export_name = "x2"]
pub extern "C" fn vmresume_failed(vmx: *mut u64) {
    log_vm_instruction_failure("VMRESUME");
    let guest_state = match GuestRootState::read_from_vmcs() {
        Ok(state) => state,
        Err(error) => {
            log::error!(
                "Failed to read guest state after VMRESUME failure: {:?}",
                error
            );
            fatal_vmx_failure_loop();
        }
    };

    if let Err(error) = Vcpu::invalidate_contexts() {
        log::error!(
            "Context invalidation before VMRESUME failure VMXOFF failed: {:?}",
            error
        );
    }

    if let Err(error) = vmxoff() {
        log::error!(
            "Failed to leave VMX operation after VMRESUME failure: {:?}",
            error
        );
        fatal_vmx_failure_loop();
    }

    if vmx.is_null() {
        log::error!("vmresume_failed received a null pointer for vmx");
        fatal_vmx_failure_loop();
    }

    let vmx = unsafe { &*(vmx as *mut Vmx) };
    unsafe {
        guest_state.restore_after_vmxoff(vmx);
    }
    clear_virtualized();
}

fn log_vm_instruction_failure(instruction: &str) {
    let instruction_error = match vmread_checked(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) {
        Ok(value) => value as u32,
        Err(error) => {
            log::error!(
                "{} failed and VM instruction error could not be read: {:?}",
                instruction,
                error
            );
            return;
        }
    };

    if let Some(error) = VmInstructionError::from_u32(instruction_error) {
        log::error!("{} instruction error: {}", instruction, error);
    } else {
        log::error!(
            "{} failed with unknown VM instruction error: {:#x}",
            instruction,
            instruction_error
        );
    }
}

fn fatal_vmx_failure_loop() -> ! {
    if let Err(error) = vmxoff() {
        log::error!(
            "Failed to leave VMX operation after fatal VMX failure: {:?}",
            error
        );
    }

    loop {
        core::hint::spin_loop();
    }
}
