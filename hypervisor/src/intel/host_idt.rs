//! Custom host IDT handlers for VMX root mode.
//!
//! Any exception/interrupt during VM exit handling goes through the host IDT
//! (a copy of the kernel IDT). Kernel handlers assume RSP is on a thread's
//! kernel stack — but in VMX root RSP is on VmStack, causing
//! FAST_FAIL_INCORRECT_STACK (BugCheck 0x139).
//!
//! This module replaces the host IDT entries for NMI (vector 2) and #GP
//! (vector 13) with minimal stubs that recover gracefully.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

// ---------------------------------------------------------------------------
// Per-CPU NMI pending flags (indexed by IA32_TSC_AUX, supports up to 256 CPUs)
// ---------------------------------------------------------------------------
const ZERO_U8: AtomicU8 = AtomicU8::new(0);
static NMI_FLAGS: [AtomicU8; 256] = [ZERO_U8; 256];

// ---------------------------------------------------------------------------
// Diagnostic counters
// ---------------------------------------------------------------------------
pub static HOST_GP_COUNT: AtomicU64 = AtomicU64::new(0);
pub static HOST_NMI_COUNT: AtomicU64 = AtomicU64::new(0);
pub static GP_FAULT_RIP: AtomicU64 = AtomicU64::new(0);

extern "C" {
    fn host_nmi_handler();
    fn host_gp_handler();
}

// ---------------------------------------------------------------------------
// Assembly: NMI handler (vector 2) — set per-CPU flag + IRET
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".global host_nmi_handler",
    "host_nmi_handler:",
    "push rax",
    "push rcx",
    "push rdx",
    // counter
    "lea rax, [rip + {nmi_count}]",
    "lock inc qword ptr [rax]",
    // per-CPU flag via rdtscp (ECX = IA32_TSC_AUX = processor number)
    "rdtscp",
    "and ecx, 0xFF",
    "lea rax, [rip + {nmi_flags}]",
    "mov byte ptr [rax + rcx], 1",
    "pop rdx",
    "pop rcx",
    "pop rax",
    "iretq",
    nmi_flags = sym NMI_FLAGS,
    nmi_count = sym HOST_NMI_COUNT,
);

// ---------------------------------------------------------------------------
// Assembly: #GP handler (vector 13) — redirect to recovery code
//
// #GP stack (IST=0, 64-bit mode, CPU pushes error code):
//   [RSP+0x00] error_code
//   [RSP+0x08] RIP
//   [RSP+0x10] CS
//   [RSP+0x18] RFLAGS
//   [RSP+0x20] RSP
//   [RSP+0x28] SS
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".global host_gp_handler",
    "host_gp_handler:",
    "push rax",
    "push rcx",
    // After 2 pushes (+16), offsets shift:
    //   error_code  +0x10
    //   RIP         +0x18
    //   CS          +0x20
    //   RFLAGS      +0x28
    //   RSP         +0x30
    //   SS          +0x38

    // counter
    "lea rax, [rip + {gp_count}]",
    "lock inc qword ptr [rax]",

    // save faulting RIP for diagnostics
    "mov rax, [rsp + 0x18]",
    "lea rcx, [rip + {gp_rip}]",
    "mov [rcx], rax",

    // read HOST_RSP from VMCS (encoding 0x6C14)
    "mov ecx, 0x6C14",
    "vmread rax, rcx",

    // patch interrupt frame: RSP → HOST_RSP
    "mov [rsp + 0x30], rax",

    // patch interrupt frame: RIP → recovery stub
    "lea rax, [rip + vmexit_recover_gp]",
    "mov [rsp + 0x18], rax",

    "pop rcx",
    "pop rax",
    "add rsp, 8",          // skip error_code
    "iretq",

    // ------ recovery: inject #GP to guest, then restore + vmresume ------
    ".global vmexit_recover_gp",
    "vmexit_recover_gp:",
    // RSP = HOST_RSP, [RSP] = GuestRegisters*
    "push rax",
    "push rcx",
    // VMENTRY_EXCEPTION_ERR_CODE (0x4018) = 0
    "mov ecx, 0x4018",
    "xor eax, eax",
    "vmwrite rcx, rax",
    // VMENTRY_INTERRUPTION_INFO_FIELD (0x4016) =
    //   valid(1<<31) | deliver_err(1<<11) | hw_exc(3<<8) | vector=13
    //   = 0x80000B0D
    "mov ecx, 0x4016",
    "mov eax, 0x80000B0D",
    "vmwrite rcx, rax",
    "pop rcx",
    "pop rax",
    "jmp vmexit_restore",

    gp_count = sym HOST_GP_COUNT,
    gp_rip   = sym GP_FAULT_RIP,
);

// ---------------------------------------------------------------------------
// Rust helpers
// ---------------------------------------------------------------------------

/// Read IA32_TSC_AUX via RDTSCP (processor number on Windows).
#[inline]
fn rdtscp_aux() -> u32 {
    let aux: u32;
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("ecx") aux,
            out("eax") _,
            out("edx") _,
            options(nomem, nostack),
        );
    }
    aux
}

/// Check for a pending NMI on this CPU and inject it to the guest.
/// Called at the end of every VM exit handler, before VMRESUME.
/// If another event is already queued for injection, the NMI stays pending
/// and will be injected on the next VM exit.
pub fn check_pending_nmi() {
    let cpu = rdtscp_aux() as usize & 0xFF;
    if NMI_FLAGS[cpu].load(Ordering::Relaxed) != 0 {
        let info = match crate::intel::support::vmread_checked(
            x86::vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
        ) {
            Ok(value) => value,
            Err(error) => {
                log::error!(
                    "Failed to read VM-entry interruption info for pending NMI: {:?}",
                    error
                );
                return;
            }
        };
        if info & (1 << 31) == 0 {
            NMI_FLAGS[cpu].store(0, Ordering::Relaxed);
            crate::intel::events::EventInjection::vmentry_inject_nmi();
        }
    }
}

// ---------------------------------------------------------------------------
// IDT patching
// ---------------------------------------------------------------------------

/// Replace host IDT vectors 2 (NMI) and 13 (#GP) with custom handlers.
/// Must be called after the host IDT is copied from the kernel IDT.
pub fn patch_host_idt(idt: &mut [u64]) {
    patch_idt_entry(idt, 2, host_nmi_handler as *const () as usize as u64);
    patch_idt_entry(idt, 13, host_gp_handler as *const () as usize as u64);
}

/// Overwrite the handler address in an x86-64 IDT entry.
/// Preserves segment selector, IST, type/attr, DPL, and present bit.
fn patch_idt_entry(idt: &mut [u64], vector: usize, handler: u64) {
    let idx = vector * 2;
    if idx + 1 >= idt.len() {
        return;
    }
    // Low qword layout:
    //   bits  0-15  offset[15:0]
    //   bits 16-47  selector | IST | type | DPL | P  (preserve)
    //   bits 48-63  offset[31:16]
    let preserved = idt[idx] & 0x0000_FFFF_FFFF_0000;
    idt[idx] = (handler & 0xFFFF) | preserved | (((handler >> 16) & 0xFFFF) << 48);
    // High qword: offset[63:32] in bits 0-31, reserved zeros in 32-63
    idt[idx + 1] = handler >> 32;
}
