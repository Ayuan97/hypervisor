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
    error::HypervisorError,
    intel::{
        diag,
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
    /// instructions `vmlaunch` and `vmresume`. A successful entry resumes at an
    /// assembly continuation and returns to the Rust caller in non-root mode.
    /// VM exits use the dedicated host stack and return to the guest via VMRESUME.
    ///
    /// # Arguments
    ///
    /// * `general_purpose_registers` - A pointer to the `GuestRegisters` structure
    /// * `host_rsp` - A pointer to the end of `stack_contents` in the `VmStack` structure.
    /// Returns zero after a successful VM entry resumes at the assembly guest
    /// continuation, or non-zero after VMLAUNCH/preparation failed and VMXOFF
    /// completed.
    pub fn launch_vm(guest_registers: &mut GuestRegisters, host_rsp: *mut u64) -> u64;

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
.set registers_mxcsr, 0x190
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
.set vmstack_host_mxcsr, 0xB0
.set vmstack_footer_from_host_rsp, 0x80
.set launch_saved_r15, 0x08
.set launch_saved_r14, 0x10
.set launch_saved_r13, 0x18
.set launch_saved_r12, 0x20
.set launch_saved_r9,  0x38
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
.set launch_host_mxcsr, 0x130

.global launch_vm
launch_vm:
    // Build the guest continuation from the exact CALL-site state. Relying on
    // RtlCaptureContext to resume in the middle of an optimized Rust function
    // made correctness depend on LLVM preserving an undocumented returns-twice
    // continuation across VMX setup.
    mov     r8, rsp
    pushfq
    pop     r9
    test    r9, 0x200
    jz      launch_vm_prepare_failed

    // From here until VM entry, RSP and the general-purpose registers no
    // longer describe a valid Windows thread context. A maskable interrupt in
    // that window would run a Windows ISR on VmStack with partially replaced
    // registers. Preserve the original flags in r9 for GUEST_RFLAGS/failure
    // recovery, then keep interrupts disabled until hardware enters non-root.
    cli

    mov     r10, 0x681C // VMCS_GUEST_RSP
    vmwrite r10, r8
    jbe     launch_vm_prepare_failed
    lea     r11, [rip + launch_vm_guest_return]
    mov     r10, 0x681E // VMCS_GUEST_RIP
    vmwrite r10, r11
    jbe     launch_vm_prepare_failed
    mov     r10, 0x6820 // VMCS_GUEST_RFLAGS
    vmwrite r10, r9
    jbe     launch_vm_prepare_failed

    // Save the original host stack and Windows x64 nonvolatile XMM registers
    // in the VmStack footer before switching RSP.
    mov     [rdx + vmstack_original_rsp], r8
    movdqu  [rdx + vmstack_host_xmm6], xmm6
    movdqu  [rdx + vmstack_host_xmm7], xmm7
    movdqu  [rdx + vmstack_host_xmm8], xmm8
    movdqu  [rdx + vmstack_host_xmm9], xmm9
    movdqu  [rdx + vmstack_host_xmm10], xmm10
    movdqu  [rdx + vmstack_host_xmm11], xmm11
    movdqu  [rdx + vmstack_host_xmm12], xmm12
    movdqu  [rdx + vmstack_host_xmm13], xmm13
    movdqu  [rdx + vmstack_host_xmm14], xmm14
    movdqu  [rdx + vmstack_host_xmm15], xmm15
    stmxcsr [rdx + vmstack_host_mxcsr]

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

    // Restore all guest XMM registers. XMM6-XMM15 are nonvolatile for the
    // Windows host ABI, but they are ordinary guest state while in non-root.
    movdqu  xmm0, [r15 + registers_xmm0]
    movdqu  xmm1, [r15 + registers_xmm1]
    movdqu  xmm2, [r15 + registers_xmm2]
    movdqu  xmm3, [r15 + registers_xmm3]
    movdqu  xmm4, [r15 + registers_xmm4]
    movdqu  xmm5, [r15 + registers_xmm5]
    movdqu  xmm6, [r15 + registers_xmm6]
    movdqu  xmm7, [r15 + registers_xmm7]
    movdqu  xmm8, [r15 + registers_xmm8]
    movdqu  xmm9, [r15 + registers_xmm9]
    movdqu  xmm10, [r15 + registers_xmm10]
    movdqu  xmm11, [r15 + registers_xmm11]
    movdqu  xmm12, [r15 + registers_xmm12]
    movdqu  xmm13, [r15 + registers_xmm13]
    movdqu  xmm14, [r15 + registers_xmm14]
    movdqu  xmm15, [r15 + registers_xmm15]
    ldmxcsr [r15 + registers_mxcsr]

    // Prepare VMCS for VM launch: set HOST_RSP and HOST_RIP.
    mov     r14, 0x6C14 // VMCS_HOST_RSP
    vmwrite r14, rsp
    jbe     launch_vm_root_failed
    lea     r13, [rip + vmexit_stub]
    mov     r14, 0x6C16 // VMCS_HOST_RIP
    vmwrite r14, r13
    jbe     launch_vm_root_failed

    // Restore additional guest registers. R11 is deliberately replaced with
    // the root-stack save-area pointer: it is volatile in the Windows x64 ABI,
    // and the VM-exit stub preserves it if an exit occurs before the guest
    // continuation has restored the caller's nonvolatile state.
    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]
    mov     r15, [r15 + registers_r15]
    mov     r11, rsp

    // Launch the VM.
    vmlaunch

launch_vm_root_failed:
    sub     rsp, 0x20
    call x1
    add     rsp, 0x20

    movdqu  xmm6, [rsp + launch_host_xmm6]
    movdqu  xmm7, [rsp + launch_host_xmm7]
    movdqu  xmm8, [rsp + launch_host_xmm8]
    movdqu  xmm9, [rsp + launch_host_xmm9]
    movdqu  xmm10, [rsp + launch_host_xmm10]
    movdqu  xmm11, [rsp + launch_host_xmm11]
    movdqu  xmm12, [rsp + launch_host_xmm12]
    movdqu  xmm13, [rsp + launch_host_xmm13]
    movdqu  xmm14, [rsp + launch_host_xmm14]
    movdqu  xmm15, [rsp + launch_host_xmm15]
    ldmxcsr [rsp + launch_host_mxcsr]

    mov     rbx, [rsp + launch_saved_rbx]
    mov     rbp, [rsp + launch_saved_rbp]
    mov     rsi, [rsp + launch_saved_rsi]
    mov     rdi, [rsp + launch_saved_rdi]
    mov     r12, [rsp + launch_saved_r12]
    mov     r13, [rsp + launch_saved_r13]
    mov     r14, [rsp + launch_saved_r14]
    mov     r15, [rsp + launch_saved_r15]

    mov     r10, [rsp + launch_saved_r9]
    mov     rax, [rsp + launch_original_rsp]
    mov     rsp, rax
    push    r10
    popfq
    mov     eax, 1
    ret

launch_vm_prepare_failed:
    // Entry RSP is 8 mod 16. Reserve shadow space plus alignment for the
    // Windows x64 call into the common VMXOFF failure handler. Preserve the
    // caller's RFLAGS outside the 32-byte shadow space: x1 may clobber r9.
    sub     rsp, 0x28
    mov     [rsp + 0x20], r9
    call    x1
    mov     r9, [rsp + 0x20]
    add     rsp, 0x28
    push    r9
    popfq
    mov     eax, 1
    ret

launch_vm_guest_return:
    // VMLAUNCH entered non-root with the original launch_vm CALL stack. The
    // caller may have live values in nonvolatile registers that differ from
    // the earlier CONTEXT snapshot, so restore the exact call-site values
    // saved on the root stack before returning to Vmx::run.
    movdqu  xmm6, [r11 + launch_host_xmm6]
    movdqu  xmm7, [r11 + launch_host_xmm7]
    movdqu  xmm8, [r11 + launch_host_xmm8]
    movdqu  xmm9, [r11 + launch_host_xmm9]
    movdqu  xmm10, [r11 + launch_host_xmm10]
    movdqu  xmm11, [r11 + launch_host_xmm11]
    movdqu  xmm12, [r11 + launch_host_xmm12]
    movdqu  xmm13, [r11 + launch_host_xmm13]
    movdqu  xmm14, [r11 + launch_host_xmm14]
    movdqu  xmm15, [r11 + launch_host_xmm15]
    ldmxcsr [r11 + launch_host_mxcsr]

    mov     rbx, [r11 + launch_saved_rbx]
    mov     rbp, [r11 + launch_saved_rbp]
    mov     rsi, [r11 + launch_saved_rsi]
    mov     rdi, [r11 + launch_saved_rdi]
    mov     r12, [r11 + launch_saved_r12]
    mov     r13, [r11 + launch_saved_r13]
    mov     r14, [r11 + launch_saved_r14]
    mov     r15, [r11 + launch_saved_r15]

    xor     eax, eax
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

    // Save all guest XMM registers before switching to host ABI state.
    movdqu  [r15 + registers_xmm0], xmm0
    movdqu  [r15 + registers_xmm1], xmm1
    movdqu  [r15 + registers_xmm2], xmm2
    movdqu  [r15 + registers_xmm3], xmm3
    movdqu  [r15 + registers_xmm4], xmm4
    movdqu  [r15 + registers_xmm5], xmm5
    movdqu  [r15 + registers_xmm6], xmm6
    movdqu  [r15 + registers_xmm7], xmm7
    movdqu  [r15 + registers_xmm8], xmm8
    movdqu  [r15 + registers_xmm9], xmm9
    movdqu  [r15 + registers_xmm10], xmm10
    movdqu  [r15 + registers_xmm11], xmm11
    movdqu  [r15 + registers_xmm12], xmm12
    movdqu  [r15 + registers_xmm13], xmm13
    movdqu  [r15 + registers_xmm14], xmm14
    movdqu  [r15 + registers_xmm15], xmm15

    // Save guest MXCSR, then load host state from the VmStack footer itself.
    // The footer begins at rsp + 0x80; the value stored there is the Vmx pointer.
    stmxcsr [r15 + registers_mxcsr]
    lea     rax, [rsp + vmstack_footer_from_host_rsp]
    movdqu  xmm6, [rax + vmstack_host_xmm6]
    movdqu  xmm7, [rax + vmstack_host_xmm7]
    movdqu  xmm8, [rax + vmstack_host_xmm8]
    movdqu  xmm9, [rax + vmstack_host_xmm9]
    movdqu  xmm10, [rax + vmstack_host_xmm10]
    movdqu  xmm11, [rax + vmstack_host_xmm11]
    movdqu  xmm12, [rax + vmstack_host_xmm12]
    movdqu  xmm13, [rax + vmstack_host_xmm13]
    movdqu  xmm14, [rax + vmstack_host_xmm14]
    movdqu  xmm15, [rax + vmstack_host_xmm15]
    ldmxcsr [rax + vmstack_host_mxcsr]

    // Set rcx to point to the saved guest registers for `vmexit_handler` (1st parameter).
    mov rcx, r15

    // Load the `Vmx` pointer stored at the footer for `vmexit_handler` (2nd parameter).
    mov rdx, [rsp + vmstack_footer_from_host_rsp]

    // Temporarily save and restore r15, keeping guest registers pointer on stack.
    mov     rax, [rsp]
    xchg    r15, [rsp]
    mov     [rcx + registers_r15], rax

    // Allocate stack space for the VM exit handler.
    sub     rsp, 0x20

    // Clear DF for safe Rust ABI string ops.
    cld

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

    // Restore all guest XMM registers for VMRESUME.
    movdqu  xmm0, [r15 + registers_xmm0]
    movdqu  xmm1, [r15 + registers_xmm1]
    movdqu  xmm2, [r15 + registers_xmm2]
    movdqu  xmm3, [r15 + registers_xmm3]
    movdqu  xmm4, [r15 + registers_xmm4]
    movdqu  xmm5, [r15 + registers_xmm5]
    movdqu  xmm6, [r15 + registers_xmm6]
    movdqu  xmm7, [r15 + registers_xmm7]
    movdqu  xmm8, [r15 + registers_xmm8]
    movdqu  xmm9, [r15 + registers_xmm9]
    movdqu  xmm10, [r15 + registers_xmm10]
    movdqu  xmm11, [r15 + registers_xmm11]
    movdqu  xmm12, [r15 + registers_xmm12]
    movdqu  xmm13, [r15 + registers_xmm13]
    movdqu  xmm14, [r15 + registers_xmm14]
    movdqu  xmm15, [r15 + registers_xmm15]

    // Restore guest MXCSR before returning to guest.
    ldmxcsr [r15 + registers_mxcsr]

    // Do this last to avoid overwriting r15.
    mov     r15, [r15 + registers_r15]

    // Attempt to resume the guest virtual machine.
    vmresume

    // If VMRESUME fails, pass both the saved GuestRegisters and Vmx pointers
    // so the handler can refresh guest RIP/RSP/RFLAGS before VMXOFF.
    mov     rcx, [rsp]
    mov     rdx, [rsp + vmstack_footer_from_host_rsp]
    lea     rax, [rsp + vmstack_footer_from_host_rsp]
    movdqu  xmm6, [rax + vmstack_host_xmm6]
    movdqu  xmm7, [rax + vmstack_host_xmm7]
    movdqu  xmm8, [rax + vmstack_host_xmm8]
    movdqu  xmm9, [rax + vmstack_host_xmm9]
    movdqu  xmm10, [rax + vmstack_host_xmm10]
    movdqu  xmm11, [rax + vmstack_host_xmm11]
    movdqu  xmm12, [rax + vmstack_host_xmm12]
    movdqu  xmm13, [rax + vmstack_host_xmm13]
    movdqu  xmm14, [rax + vmstack_host_xmm14]
    movdqu  xmm15, [rax + vmstack_host_xmm15]
    ldmxcsr [rax + vmstack_host_mxcsr]
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

    // Restore all guest XMMs before returning to the guest after VMXOFF.
    movdqu  xmm0, [r15 + registers_xmm0]
    movdqu  xmm1, [r15 + registers_xmm1]
    movdqu  xmm2, [r15 + registers_xmm2]
    movdqu  xmm3, [r15 + registers_xmm3]
    movdqu  xmm4, [r15 + registers_xmm4]
    movdqu  xmm5, [r15 + registers_xmm5]
    movdqu  xmm6, [r15 + registers_xmm6]
    movdqu  xmm7, [r15 + registers_xmm7]
    movdqu  xmm8, [r15 + registers_xmm8]
    movdqu  xmm9, [r15 + registers_xmm9]
    movdqu  xmm10, [r15 + registers_xmm10]
    movdqu  xmm11, [r15 + registers_xmm11]
    movdqu  xmm12, [r15 + registers_xmm12]
    movdqu  xmm13, [r15 + registers_xmm13]
    movdqu  xmm14, [r15 + registers_xmm14]
    movdqu  xmm15, [r15 + registers_xmm15]
    ldmxcsr [r15 + registers_mxcsr]

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
        Ok(_) => {
            // `HandlerGuard` has dropped before this branch executes. Keep a
            // durable phase for the short assembly window between Rust return
            // and VMRESUME; a freeze there is otherwise invisible.
            crate::intel::diag::cpu_enter_phase(crate::intel::diag::PHASE_VMRESUME_STUB);
            0
        }
        Err(error) => {
            crate::intel::diag::cpu_enter_phase(crate::intel::diag::PHASE_ERROR_HANDLER);
            // VM-entry failure already has a dedicated terminal record with
            // VM_INSTRUCTION_ERROR. Do not overwrite it with a generic Rust
            // handler error while performing VMXOFF recovery.
            if !matches!(error, HypervisorError::VMRESUMEFailed) {
                let _ = crate::intel::terminal_capture::force_current(
                    crate::intel::terminal_capture::KIND_HANDLER_ERROR,
                    crate::intel::terminal_capture::INVALID_VM_ERROR,
                    0,
                );
            }
            match vmexit.recover_from_handler_error(registers, vmx) {
                Ok(()) => 1,
                Err(recovery_error) => {
                    log::error!(
                        "VM-exit handler failed ({:?}) and recovery failed ({:?})",
                        error,
                        recovery_error
                    );
                    let _ = crate::intel::terminal_capture::force_current(
                        crate::intel::terminal_capture::KIND_HANDLER_ERROR,
                        crate::intel::terminal_capture::INVALID_VM_ERROR,
                        1,
                    );
                    fatal_vmx_failure_loop()
                }
            }
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
    diag::cpu_enter_phase(diag::PHASE_VM_ENTRY_FAILED);
    log_vm_instruction_failure("VMLAUNCH", 1);
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
pub unsafe extern "C" fn vmresume_failed(registers: *mut GuestRegisters, vmx: *mut u64) {
    diag::cpu_enter_phase(diag::PHASE_VMRESUME_FAILED);
    log_vm_instruction_failure("VMRESUME", 2);
    if registers.is_null() {
        log::error!("vmresume_failed received a null pointer for guest registers");
        fatal_vmx_failure_loop();
    }
    if vmx.is_null() {
        log::error!("vmresume_failed received a null pointer for vmx");
        fatal_vmx_failure_loop();
    }

    let registers = &mut *registers;
    registers.rip = match vmread_checked(x86::vmx::vmcs::guest::RIP) {
        Ok(value) => value,
        Err(error) => {
            log::error!("Failed to read guest RIP after VMRESUME failure: {:?}", error);
            fatal_vmx_failure_loop();
        }
    };
    registers.rsp = match vmread_checked(x86::vmx::vmcs::guest::RSP) {
        Ok(value) => value,
        Err(error) => {
            log::error!("Failed to read guest RSP after VMRESUME failure: {:?}", error);
            fatal_vmx_failure_loop();
        }
    };
    registers.rflags = match vmread_checked(x86::vmx::vmcs::guest::RFLAGS) {
        Ok(value) => value,
        Err(error) => {
            log::error!(
                "Failed to read guest RFLAGS after VMRESUME failure: {:?}",
                error
            );
            fatal_vmx_failure_loop();
        }
    };

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

    let vmx = &*(vmx as *mut Vmx);
    guest_state.restore_after_vmxoff(vmx);
    vmx.restore_guest_transition_msrs();
    clear_virtualized();
}

fn log_vm_instruction_failure(instruction: &str, kind: u64) {
    use core::sync::atomic::Ordering::Relaxed;

    diag::LAST_VM_INSTRUCTION_KIND.store(kind, Relaxed);
    let instruction_error = match vmread_checked(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) {
        Ok(value) => value as u32,
        Err(error) => {
            diag::LAST_VM_INSTRUCTION_ERROR.store(u64::MAX, Relaxed);
            log::error!(
                "{} failed and VM instruction error could not be read: {:?}",
                instruction,
                error
            );
            let terminal_kind = if kind == 2 {
                crate::intel::terminal_capture::KIND_VMRESUME_FAILURE
            } else {
                crate::intel::terminal_capture::KIND_VM_ENTRY_FAILURE
            };
            let _ = crate::intel::terminal_capture::force_current(
                terminal_kind,
                crate::intel::terminal_capture::INVALID_VM_ERROR,
                kind as u8,
            );
            diag::capture_vmcs_guest_state();
            return;
        }
    };
    diag::LAST_VM_INSTRUCTION_ERROR.store(instruction_error as u64, Relaxed);

    // Persist the instruction error before the more extensive VMCS reads
    // below. A later VMREAD can itself fail or the machine can stop here.
    let terminal_kind = if kind == 2 {
        crate::intel::terminal_capture::KIND_VMRESUME_FAILURE
    } else {
        crate::intel::terminal_capture::KIND_VM_ENTRY_FAILURE
    };
    let _ = crate::intel::terminal_capture::force_current(
        terminal_kind,
        instruction_error as u8,
        kind as u8,
    );

    diag::capture_vmcs_guest_state();
    diag::LAST_VMENTRY_INTERRUPTION_INFO.store(
        vmread_checked(x86::vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD)
            .unwrap_or(u64::MAX),
        Relaxed,
    );
    diag::LAST_GUEST_INTERRUPTIBILITY.store(
        vmread_checked(x86::vmx::vmcs::guest::INTERRUPTIBILITY_STATE).unwrap_or(u64::MAX),
        Relaxed,
    );
    diag::LAST_GUEST_ACTIVITY_STATE.store(
        vmread_checked(x86::vmx::vmcs::guest::ACTIVITY_STATE).unwrap_or(u64::MAX),
        Relaxed,
    );
    diag::LAST_GUEST_PENDING_DEBUG.store(
        vmread_checked(x86::vmx::vmcs::guest::PENDING_DBG_EXCEPTIONS).unwrap_or(u64::MAX),
        Relaxed,
    );

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
    fatal_vmx_failure_loop_pub()
}

pub fn fatal_vmx_failure_loop_pub() -> ! {
    let _ = crate::intel::terminal_capture::force_current(
        crate::intel::terminal_capture::KIND_HANDLER_ERROR,
        crate::intel::terminal_capture::INVALID_VM_ERROR,
        0xff,
    );
    if let Err(error) = vmxoff() {
        log::error!(
            "Failed to leave VMX operation after fatal VMX failure: {:?}",
            error
        );
    }

    // STI before HLT so IPIs can still reach this CPU; prevents cascade freeze.
    loop {
        unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)) };
    }
}
