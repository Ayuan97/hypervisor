use crate::{intel::vmexit::ExitType, utils::capture::GuestRegisters};

pub const VMCALL_MAGIC: u64 = 0x4879_7065_7256_4D00;

pub const CMD_PING: u64 = 0x01;
pub const CMD_READ_PHYS: u64 = 0x10;
pub const CMD_WRITE_PHYS: u64 = 0x11;
pub const CMD_TRANSLATE_VA: u64 = 0x12;
pub const CMD_DEVIRTUALIZE: u64 = 0xFF;

/// Handle VMCALL from guest.
///
/// If RAX matches our magic, dispatch by command in RCX.
/// Otherwise return None to let the caller inject #UD.
pub fn handle_vmcall(guest_registers: &mut GuestRegisters) -> Option<ExitType> {
    if guest_registers.rax != VMCALL_MAGIC {
        return None;
    }

    let cmd = guest_registers.rcx;
    let arg1 = guest_registers.rdx;
    let arg2 = guest_registers.r8;
    let arg3 = guest_registers.r9;

    match cmd {
        CMD_PING => {
            guest_registers.rax = VMCALL_MAGIC;
            Some(ExitType::IncrementRIP)
        }
        CMD_READ_PHYS => {
            let pa = arg1;
            let len = arg2 as usize;
            let out_buf = arg3 as *mut u8;

            if len == 0 || len > 0x10000 || out_buf.is_null() {
                guest_registers.rax = 1; // error
                return Some(ExitType::IncrementRIP);
            }

            unsafe {
                let src = pa as *const u8;
                core::ptr::copy_nonoverlapping(src, out_buf, len);
            }

            guest_registers.rax = 0;
            Some(ExitType::IncrementRIP)
        }
        CMD_WRITE_PHYS => {
            let pa = arg1;
            let len = arg2 as usize;
            let in_buf = arg3 as *const u8;

            if len == 0 || len > 0x10000 || in_buf.is_null() {
                guest_registers.rax = 1;
                return Some(ExitType::IncrementRIP);
            }

            unsafe {
                let dst = pa as *mut u8;
                core::ptr::copy_nonoverlapping(in_buf, dst, len);
            }

            guest_registers.rax = 0;
            Some(ExitType::IncrementRIP)
        }
        CMD_TRANSLATE_VA => {
            let target_cr3 = arg1;
            let va = arg2;
            match translate_va_to_pa(target_cr3, va) {
                Some(pa) => guest_registers.rax = pa,
                None => guest_registers.rax = 0,
            }
            Some(ExitType::IncrementRIP)
        }
        CMD_DEVIRTUALIZE => {
            guest_registers.rax = VMCALL_MAGIC;
            Some(ExitType::ExitHypervisor)
        }
        _ => {
            guest_registers.rax = u64::MAX;
            Some(ExitType::IncrementRIP)
        }
    }
}

/// Walk the guest page tables to translate VA → PA.
fn translate_va_to_pa(cr3: u64, va: u64) -> Option<u64> {
    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;
    let offset = va & 0xFFF;

    unsafe {
        let pml4e = *((pml4_base + pml4_idx * 8) as *const u64);
        if pml4e & 1 == 0 {
            return None;
        }

        let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
        let pdpte = *((pdpt_base + pdpt_idx * 8) as *const u64);
        if pdpte & 1 == 0 {
            return None;
        }
        // 1GB page
        if pdpte & 0x80 != 0 {
            let pa = (pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF);
            return Some(pa);
        }

        let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
        let pde = *((pd_base + pd_idx * 8) as *const u64);
        if pde & 1 == 0 {
            return None;
        }
        // 2MB page
        if pde & 0x80 != 0 {
            let pa = (pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF);
            return Some(pa);
        }

        let pt_base = pde & 0x000F_FFFF_FFFF_F000;
        let pte = *((pt_base + pt_idx * 8) as *const u64);
        if pte & 1 == 0 {
            return None;
        }

        let pa = (pte & 0x000F_FFFF_FFFF_F000) | offset;
        Some(pa)
    }
}
