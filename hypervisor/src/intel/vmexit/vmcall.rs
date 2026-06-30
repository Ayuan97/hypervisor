use {
    crate::{
        intel::{
            ept::paging::AccessType, invept::invept_all_contexts, support::vmread_checked,
            vmexit::ExitType, vmx::Vmx,
        },
        utils::capture::GuestRegisters,
    },
    wdk_sys::{
        ntddk::MmCopyMemory, _MM_COPY_ADDRESS__bindgen_ty_1, MM_COPY_ADDRESS,
        MM_COPY_MEMORY_PHYSICAL, NT_SUCCESS, PHYSICAL_ADDRESS,
    },
    x86::vmx::vmcs::guest,
};

pub const VMCALL_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
pub const CPUID_COMM_LEAF: u32 = 0x7A3F_E1D9;
const STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;
const STATUS_UNSUPPORTED_COMMAND: u64 = u64::MAX - 2;

const CMD_PING: u64 = 0x01;
const CMD_READ_PHYS: u64 = 0x10;
const CMD_WRITE_PHYS: u64 = 0x11;
const CMD_TRANSLATE_VA: u64 = 0x12;
const CMD_GET_GUEST_CR3: u64 = 0x13;
const CMD_GET_COUNTER: u64 = 0x14;
const CMD_GET_CTL: u64 = 0x15;
const CMD_CLOAK_PAGE: u64 = 0x20;
const CMD_DEVIRTUALIZE: u64 = 0xFF;

fn cs_selector_is_ring0(selector: u64) -> bool {
    selector & 0x3 == 0
}

fn command_requires_ring0(cmd: u64) -> bool {
    matches!(
        cmd,
        CMD_READ_PHYS | CMD_WRITE_PHYS | CMD_TRANSLATE_VA | CMD_CLOAK_PAGE | CMD_DEVIRTUALIZE
    )
}

fn physical_access_size_is_valid(size: usize) -> bool {
    (1..=8).contains(&size)
}

fn physical_writes_are_enabled() -> bool {
    false
}

fn physical_copy_address(pa: u64) -> MM_COPY_ADDRESS {
    MM_COPY_ADDRESS {
        __bindgen_anon_1: _MM_COPY_ADDRESS__bindgen_ty_1 {
            PhysicalAddress: PHYSICAL_ADDRESS {
                QuadPart: pa as i64,
            },
        },
    }
}

fn read_phys_sized(pa: u64, size: usize) -> Option<u64> {
    if !physical_access_size_is_valid(size) {
        return None;
    }

    let mut buffer = [0u8; 8];
    let mut bytes_transferred = 0u64;
    let status = unsafe {
        MmCopyMemory(
            buffer.as_mut_ptr().cast(),
            physical_copy_address(pa),
            size as u64,
            MM_COPY_MEMORY_PHYSICAL,
            &mut bytes_transferred,
        )
    };

    (NT_SUCCESS(status) && bytes_transferred == size as u64).then(|| u64::from_le_bytes(buffer))
}

fn read_page_table_entry(pa: u64) -> Option<u64> {
    read_phys_sized(pa, 8)
}

pub fn dispatch_command(guest_registers: &mut GuestRegisters, vmx: &mut Vmx) -> ExitType {
    let cmd = guest_registers.rcx;
    let arg1 = guest_registers.rdx;
    let arg2 = guest_registers.r8;

    if command_requires_ring0(cmd) {
        let guest_cs = match vmread_checked(guest::CS_SELECTOR) {
            Ok(value) => value,
            Err(error) => {
                log::error!("Failed to read guest CS selector for VMCALL: {:?}", error);
                guest_registers.rax = STATUS_ACCESS_DENIED;
                return ExitType::IncrementRIP;
            }
        };

        if !cs_selector_is_ring0(guest_cs) {
            guest_registers.rax = STATUS_ACCESS_DENIED;
            return ExitType::IncrementRIP;
        }
    }

    match cmd {
        CMD_PING => {
            guest_registers.rax = VMCALL_MAGIC;
            ExitType::IncrementRIP
        }
        CMD_READ_PHYS => {
            let pa = arg1;
            let size = arg2 as usize;
            guest_registers.rax = read_phys_sized(pa, size).unwrap_or(0);
            ExitType::IncrementRIP
        }
        CMD_WRITE_PHYS => {
            if physical_writes_are_enabled() {
                log::error!("Physical write VMCALL is enabled without a safe writer implementation");
            }
            guest_registers.rax = STATUS_UNSUPPORTED_COMMAND;
            ExitType::IncrementRIP
        }
        CMD_TRANSLATE_VA => {
            let cr3 = arg1;
            let va = arg2;
            guest_registers.rax = translate_va_to_pa(cr3, va).unwrap_or(0);
            ExitType::IncrementRIP
        }
        CMD_GET_GUEST_CR3 => {
            guest_registers.rax = match vmread_checked(guest::CR3) {
                Ok(value) => value,
                Err(error) => {
                    log::error!("Failed to read guest CR3 for VMCALL: {:?}", error);
                    0
                }
            };
            ExitType::IncrementRIP
        }
        CMD_GET_COUNTER => {
            guest_registers.rax = crate::intel::diag::counter(arg1);
            ExitType::IncrementRIP
        }
        CMD_GET_CTL => {
            guest_registers.rax = crate::intel::diag::control(arg1);
            ExitType::IncrementRIP
        }
        CMD_CLOAK_PAGE => {
            let pa = arg1 & !0xFFF;
            let shared_data = unsafe { vmx.shared_data.as_mut() };
            let ept = &mut shared_data.primary_ept;

            let split_ok = ept
                .split_2mb_to_4kb(pa, AccessType::READ_WRITE_EXECUTE)
                .or_else(|e| {
                    if matches!(e, crate::error::HypervisorError::PageAlreadySplit) {
                        Ok(())
                    } else {
                        Err(e)
                    }
                });

            if split_ok.is_ok() {
                if ept.set_page_access(pa, AccessType::empty()).is_ok() {
                    invept_all_contexts();
                    guest_registers.rax = 0;
                } else {
                    guest_registers.rax = 2;
                }
            } else {
                guest_registers.rax = 1;
            }
            ExitType::IncrementRIP
        }
        CMD_DEVIRTUALIZE => {
            guest_registers.rax = u64::MAX;
            ExitType::IncrementRIP
        }
        _ => {
            guest_registers.rax = u64::MAX;
            ExitType::IncrementRIP
        }
    }
}

fn translate_va_to_pa(cr3: u64, va: u64) -> Option<u64> {
    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;
    let offset = va & 0xFFF;

    let pml4e = read_page_table_entry(pml4_base + pml4_idx * 8)?;
    if pml4e & 1 == 0 {
        return None;
    }

    let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
    let pdpte = read_page_table_entry(pdpt_base + pdpt_idx * 8)?;
    if pdpte & 1 == 0 {
        return None;
    }
    if pdpte & 0x80 != 0 {
        return Some((pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF));
    }

    let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
    let pde = read_page_table_entry(pd_base + pd_idx * 8)?;
    if pde & 1 == 0 {
        return None;
    }
    if pde & 0x80 != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }

    let pt_base = pde & 0x000F_FFFF_FFFF_F000;
    let pte = read_page_table_entry(pt_base + pt_idx * 8)?;
    if pte & 1 == 0 {
        return None;
    }

    Some((pte & 0x000F_FFFF_FFFF_F000) | offset)
}

pub fn handle_vmcall(guest_registers: &mut GuestRegisters, vmx: &mut Vmx) -> Option<ExitType> {
    if guest_registers.rax != VMCALL_MAGIC {
        return None;
    }
    Some(dispatch_command(guest_registers, vmx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring0_selector_is_privileged() {
        assert!(cs_selector_is_ring0(0x10));
        assert!(!cs_selector_is_ring0(0x33));
    }

    #[test]
    fn physical_access_size_must_fit_native_read_width() {
        assert!(physical_access_size_is_valid(1));
        assert!(physical_access_size_is_valid(8));
        assert!(!physical_access_size_is_valid(0));
        assert!(!physical_access_size_is_valid(9));
    }

    #[test]
    fn physical_write_command_is_disabled_by_default() {
        assert!(!physical_writes_are_enabled());
    }

    #[test]
    fn dangerous_commands_require_ring0() {
        assert!(!command_requires_ring0(CMD_PING));
        assert!(!command_requires_ring0(CMD_GET_COUNTER));
        assert!(!command_requires_ring0(CMD_GET_CTL));
        assert!(command_requires_ring0(CMD_READ_PHYS));
        assert!(command_requires_ring0(CMD_WRITE_PHYS));
        assert!(command_requires_ring0(CMD_TRANSLATE_VA));
        assert!(command_requires_ring0(CMD_CLOAK_PAGE));
        assert!(command_requires_ring0(CMD_DEVIRTUALIZE));
    }
}
