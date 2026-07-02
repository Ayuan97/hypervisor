//! Custom host IDT handlers for VMX root mode.
//!
//! Any exception/interrupt during VM exit handling goes through the host IDT
//! (a copy of the kernel IDT). Kernel handlers assume RSP is on a thread's
//! kernel stack — but in VMX root RSP is on VmStack, causing
//! FAST_FAIL_INCORRECT_STACK (BugCheck 0x139).
//!
//! This module replaces selected host IDT entries with minimal VMX-root stubs.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

// ---------------------------------------------------------------------------
// Per-CPU NMI pending flags (indexed by IA32_TSC_AUX, supports up to 256 CPUs)
// ---------------------------------------------------------------------------
const ZERO_U8: AtomicU8 = AtomicU8::new(0);
const ZERO_U64: AtomicU64 = AtomicU64::new(0);
static NMI_FLAGS: [AtomicU8; 256] = [ZERO_U8; 256];
static MC_FLAGS: [AtomicU8; 256] = [ZERO_U8; 256];
static HOST_IDT_PATCH_MASK: [AtomicU64; 256] = [ZERO_U64; 256];
static HOST_IDT_BASE: [AtomicU64; 256] = [ZERO_U64; 256];
static HOST_IDT_LIMIT: [AtomicU64; 256] = [ZERO_U64; 256];
static HOST_IDT_NMI_TARGET: [AtomicU64; 256] = [ZERO_U64; 256];
static HOST_IDT_GP_TARGET: [AtomicU64; 256] = [ZERO_U64; 256];
static HOST_IDT_PF_TARGET: [AtomicU64; 256] = [ZERO_U64; 256];
static HOST_IDT_MC_TARGET: [AtomicU64; 256] = [ZERO_U64; 256];

// ---------------------------------------------------------------------------
// Diagnostic counters
// ---------------------------------------------------------------------------
pub static HOST_GP_COUNT: AtomicU64 = AtomicU64::new(0);
pub static HOST_NMI_COUNT: AtomicU64 = AtomicU64::new(0);
pub static HOST_MC_COUNT: AtomicU64 = AtomicU64::new(0);
pub static HOST_PF_COUNT: AtomicU64 = AtomicU64::new(0);
pub static GP_FAULT_RIP: AtomicU64 = AtomicU64::new(0);
pub static PF_FAULT_RIP: AtomicU64 = AtomicU64::new(0);
pub static PF_FAULT_CR2: AtomicU64 = AtomicU64::new(0);
pub static MC_FAULT_RIP: AtomicU64 = AtomicU64::new(0);
pub static HOST_IDT_PATCH_CALLS: AtomicU64 = AtomicU64::new(0);
pub static HOST_IDT_PATCH_OK_CALLS: AtomicU64 = AtomicU64::new(0);

pub const HOST_IDT_PATCH_NMI_MATCH: u64 = 1 << 0;
pub const HOST_IDT_PATCH_GP_MATCH: u64 = 1 << 1;
pub const HOST_IDT_PATCH_MC_MATCH: u64 = 1 << 2;
pub const HOST_IDT_PATCH_BASE_PRESENT: u64 = 1 << 3;
pub const HOST_IDT_PATCH_LIMIT_COVERS_MC: u64 = 1 << 4;
pub const HOST_IDT_PATCH_PF_MATCH: u64 = 1 << 5;
pub const HOST_IDT_PATCH_ALL: u64 = HOST_IDT_PATCH_NMI_MATCH
    | HOST_IDT_PATCH_GP_MATCH
    | HOST_IDT_PATCH_MC_MATCH
    | HOST_IDT_PATCH_BASE_PRESENT
    | HOST_IDT_PATCH_LIMIT_COVERS_MC
    | HOST_IDT_PATCH_PF_MATCH;

extern "C" {
    fn host_nmi_handler();
    fn host_gp_handler();
    fn host_pf_handler();
    fn host_mc_handler();
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
// Assembly: #MC handler (vector 18) - set per-CPU flag + IRET
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".global host_mc_handler",
    "host_mc_handler:",
    "push rax",
    "push rcx",
    "push rdx",
    // counter
    "lea rax, [rip + {mc_count}]",
    "lock inc qword ptr [rax]",
    // save interrupted RIP for diagnostics; #MC does not push an error code
    "mov rax, [rsp + 0x18]",
    "lea rcx, [rip + {mc_rip}]",
    "mov [rcx], rax",
    // per-CPU flag via rdtscp (ECX = IA32_TSC_AUX = processor number)
    "rdtscp",
    "and ecx, 0xFF",
    "lea rax, [rip + {mc_flags}]",
    "mov byte ptr [rax + rcx], 1",
    "pop rdx",
    "pop rcx",
    "pop rax",
    "iretq",
    mc_flags = sym MC_FLAGS,
    mc_count = sym HOST_MC_COUNT,
    mc_rip   = sym MC_FAULT_RIP,
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
// Assembly: #PF handler (vector 14) - record + recover to guest
//
// #PF stack (IST=0, 64-bit mode, CPU pushes error code):
//   [RSP+0x00] error_code
//   [RSP+0x08] RIP
//   [RSP+0x10] CS
//   [RSP+0x18] RFLAGS
//   [RSP+0x20] RSP
//   [RSP+0x28] SS
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".global host_pf_handler",
    "host_pf_handler:",
    "push rax",
    "push rcx",

    // counter
    "lea rax, [rip + {pf_count}]",
    "lock inc qword ptr [rax]",

    // After 2 pushes (+16), offsets shift:
    //   error_code  +0x10
    //   RIP         +0x18
    //   RSP         +0x30
    "mov rax, [rsp + 0x18]",
    "lea rcx, [rip + {pf_rip}]",
    "mov [rcx], rax",

    "mov rax, cr2",
    "lea rcx, [rip + {pf_cr2}]",
    "mov [rcx], rax",

    // Preserve the root #PF error code for the injected guest event.
    "mov rax, [rsp + 0x10]",
    "mov ecx, 0x4018",
    "vmwrite rcx, rax",

    // read HOST_RSP from VMCS (encoding 0x6C14)
    "mov ecx, 0x6C14",
    "vmread rax, rcx",

    // patch interrupt frame: RSP -> HOST_RSP
    "mov [rsp + 0x30], rax",

    // patch interrupt frame: RIP -> recovery stub
    "lea rax, [rip + vmexit_recover_pf]",
    "mov [rsp + 0x18], rax",

    "pop rcx",
    "pop rax",
    "add rsp, 8",          // skip error_code
    "iretq",

    ".global vmexit_recover_pf",
    "vmexit_recover_pf:",
    // RSP = HOST_RSP, [RSP] = GuestRegisters*
    "push rax",
    "push rcx",
    // VMENTRY_INTERRUPTION_INFO_FIELD (0x4016) =
    //   valid(1<<31) | deliver_err(1<<11) | hw_exc(3<<8) | vector=14
    //   = 0x80000B0E
    "mov ecx, 0x4016",
    "mov eax, 0x80000B0E",
    "vmwrite rcx, rax",
    "pop rcx",
    "pop rax",
    "jmp vmexit_restore",

    pf_count = sym HOST_PF_COUNT,
    pf_rip   = sym PF_FAULT_RIP,
    pf_cr2   = sym PF_FAULT_CR2,
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
    if NMI_FLAGS[cpu].load(Ordering::Relaxed) != 0 || MC_FLAGS[cpu].load(Ordering::Relaxed) != 0 {
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
            if MC_FLAGS[cpu].load(Ordering::Relaxed) != 0 {
                MC_FLAGS[cpu].store(0, Ordering::Relaxed);
                crate::intel::events::EventInjection::vmentry_inject_machine_check();
            } else {
                NMI_FLAGS[cpu].store(0, Ordering::Relaxed);
                crate::intel::events::EventInjection::vmentry_inject_nmi();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IDT patching
// ---------------------------------------------------------------------------

/// Replace selected host IDT vectors with custom handlers.
/// Must be called after the host IDT is copied from the kernel IDT.
pub fn patch_host_idt(idt: &mut [u64]) {
    patch_idt_entry(idt, 2, expected_nmi_handler());
    patch_idt_entry(idt, 13, expected_gp_handler());
    patch_idt_entry(idt, 14, expected_pf_handler());
    patch_idt_entry(idt, 18, expected_mc_handler());
}

pub fn record_host_idt_descriptor(idt: &[u64], base: u64, limit: u64) {
    let cpu = current_cpu_index();
    let nmi_target = idt_entry_handler(idt, 2).unwrap_or(0);
    let gp_target = idt_entry_handler(idt, 13).unwrap_or(0);
    let pf_target = idt_entry_handler(idt, 14).unwrap_or(0);
    let mc_target = idt_entry_handler(idt, 18).unwrap_or(0);
    let mask = host_idt_patch_mask(idt, base, limit);

    HOST_IDT_PATCH_MASK[cpu].store(mask, Ordering::Relaxed);
    HOST_IDT_BASE[cpu].store(base, Ordering::Relaxed);
    HOST_IDT_LIMIT[cpu].store(limit, Ordering::Relaxed);
    HOST_IDT_NMI_TARGET[cpu].store(nmi_target, Ordering::Relaxed);
    HOST_IDT_GP_TARGET[cpu].store(gp_target, Ordering::Relaxed);
    HOST_IDT_PF_TARGET[cpu].store(pf_target, Ordering::Relaxed);
    HOST_IDT_MC_TARGET[cpu].store(mc_target, Ordering::Relaxed);
    HOST_IDT_PATCH_CALLS.fetch_add(1, Ordering::Relaxed);
    if mask == HOST_IDT_PATCH_ALL {
        HOST_IDT_PATCH_OK_CALLS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn current_cpu_index() -> usize {
    rdtscp_aux() as usize & 0xFF
}

pub fn current_patch_mask() -> u64 {
    HOST_IDT_PATCH_MASK[current_cpu_index()].load(Ordering::Relaxed)
}

pub fn current_host_idt_base() -> u64 {
    HOST_IDT_BASE[current_cpu_index()].load(Ordering::Relaxed)
}

pub fn current_host_idt_limit() -> u64 {
    HOST_IDT_LIMIT[current_cpu_index()].load(Ordering::Relaxed)
}

pub fn current_nmi_target() -> u64 {
    HOST_IDT_NMI_TARGET[current_cpu_index()].load(Ordering::Relaxed)
}

pub fn current_gp_target() -> u64 {
    HOST_IDT_GP_TARGET[current_cpu_index()].load(Ordering::Relaxed)
}

pub fn current_pf_target() -> u64 {
    HOST_IDT_PF_TARGET[current_cpu_index()].load(Ordering::Relaxed)
}

pub fn current_mc_target() -> u64 {
    HOST_IDT_MC_TARGET[current_cpu_index()].load(Ordering::Relaxed)
}

pub fn expected_nmi_handler() -> u64 {
    host_nmi_handler as *const () as usize as u64
}

pub fn expected_gp_handler() -> u64 {
    host_gp_handler as *const () as usize as u64
}

pub fn expected_pf_handler() -> u64 {
    host_pf_handler as *const () as usize as u64
}

pub fn expected_mc_handler() -> u64 {
    host_mc_handler as *const () as usize as u64
}

fn host_idt_patch_mask(idt: &[u64], base: u64, limit: u64) -> u64 {
    let mut mask = 0;
    if idt_entry_handler(idt, 2) == Some(expected_nmi_handler()) {
        mask |= HOST_IDT_PATCH_NMI_MATCH;
    }
    if idt_entry_handler(idt, 13) == Some(expected_gp_handler()) {
        mask |= HOST_IDT_PATCH_GP_MATCH;
    }
    if idt_entry_handler(idt, 14) == Some(expected_pf_handler()) {
        mask |= HOST_IDT_PATCH_PF_MATCH;
    }
    if idt_entry_handler(idt, 18) == Some(expected_mc_handler()) {
        mask |= HOST_IDT_PATCH_MC_MATCH;
    }
    if base != 0 {
        mask |= HOST_IDT_PATCH_BASE_PRESENT;
    }
    if limit as usize >= (18 * 16 + 15) {
        mask |= HOST_IDT_PATCH_LIMIT_COVERS_MC;
    }
    mask
}

fn idt_entry_handler(idt: &[u64], vector: usize) -> Option<u64> {
    let idx = vector.checked_mul(2)?;
    if idx + 1 >= idt.len() {
        return None;
    }

    let low = idt[idx];
    let high = idt[idx + 1];
    Some((low & 0xFFFF) | (((low >> 48) & 0xFFFF) << 16) | ((high & 0xFFFF_FFFF) << 32))
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

#[cfg(test)]
mod tests {
    use super::*;

    const PRESERVED_BITS: u64 = 0x0000_ABCD_1234_0000;

    fn blank_idt() -> alloc::vec::Vec<u64> {
        let mut idt = alloc::vec![0u64; 40];
        idt[2 * 2] = PRESERVED_BITS;
        idt[13 * 2] = PRESERVED_BITS;
        idt[14 * 2] = PRESERVED_BITS;
        idt[18 * 2] = PRESERVED_BITS;
        idt
    }

    #[test]
    fn patch_host_idt_points_nmi_and_gp_at_custom_handlers() {
        let mut idt = blank_idt();

        patch_host_idt(&mut idt);

        assert_eq!(idt_entry_handler(&idt, 2), Some(expected_nmi_handler()));
        assert_eq!(idt_entry_handler(&idt, 13), Some(expected_gp_handler()));
        assert_eq!(idt_entry_handler(&idt, 14), Some(expected_pf_handler()));
        assert_eq!(idt_entry_handler(&idt, 18), Some(expected_mc_handler()));
        assert_eq!(idt[2 * 2] & 0x0000_FFFF_FFFF_0000, PRESERVED_BITS);
        assert_eq!(idt[13 * 2] & 0x0000_FFFF_FFFF_0000, PRESERVED_BITS);
        assert_eq!(idt[14 * 2] & 0x0000_FFFF_FFFF_0000, PRESERVED_BITS);
        assert_eq!(idt[18 * 2] & 0x0000_FFFF_FFFF_0000, PRESERVED_BITS);
    }

    #[test]
    fn patch_host_idt_replaces_machine_check_vector() {
        let mut idt = blank_idt();
        let original = idt_entry_handler(&idt, 18);

        patch_host_idt(&mut idt);

        assert_ne!(idt_entry_handler(&idt, 18), original);
        assert_eq!(idt[18 * 2] & 0x0000_FFFF_FFFF_0000, PRESERVED_BITS);
    }

    #[test]
    fn patch_host_idt_replaces_page_fault_vector() {
        let mut idt = blank_idt();
        let original = idt_entry_handler(&idt, 14);

        patch_host_idt(&mut idt);

        assert_ne!(idt_entry_handler(&idt, 14), original);
        assert_eq!(idt_entry_handler(&idt, 14), Some(expected_pf_handler()));
        assert_eq!(idt[14 * 2] & 0x0000_FFFF_FFFF_0000, PRESERVED_BITS);
    }

    #[test]
    fn host_idt_patch_mask_requires_handlers_base_and_limit() {
        let mut idt = blank_idt();
        patch_host_idt(&mut idt);

        assert_eq!(
            host_idt_patch_mask(&idt, 0x1000, 0x0FFF),
            HOST_IDT_PATCH_ALL
        );
        assert_eq!(
            host_idt_patch_mask(&idt, 0, 0x0FFF) & HOST_IDT_PATCH_BASE_PRESENT,
            0
        );
        assert_eq!(
            host_idt_patch_mask(&idt, 0x1000, 0) & HOST_IDT_PATCH_LIMIT_COVERS_MC,
            0
        );
    }
}
