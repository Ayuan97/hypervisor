use {
    crate::{
        intel::{
            support::{vmread_checked, vmwrite_checked},
            vmexit::ExitType,
        },
        utils::capture::GuestRegisters,
    },
    x86::vmx::vmcs,
};

const CR4_VMXE: u64 = 1 << 13;

pub fn handle_cr_access(guest_registers: &mut GuestRegisters) -> ExitType {
    let qualification = match vmread_checked(vmcs::ro::EXIT_QUALIFICATION) {
        Ok(value) => value,
        Err(error) => {
            log::error!("Failed to read CR access qualification: {:?}", error);
            return super::exception::handle_undefined_opcode_exception();
        }
    };
    let cr_number = qualification & 0xF;
    let access_type = (qualification >> 4) & 0x3;
    let reg_index = ((qualification >> 8) & 0xF) as u8;

    if cr_number == 4 && access_type == 0 {
        let value = read_gpr(guest_registers, reg_index);
        if let Err(error) = vmwrite_checked(vmcs::guest::CR4, value | CR4_VMXE) {
            log::error!("Failed to write guest CR4: {:?}", error);
            return super::exception::handle_undefined_opcode_exception();
        }
        if let Err(error) = vmwrite_checked(vmcs::control::CR4_READ_SHADOW, value & !CR4_VMXE) {
            log::error!("Failed to write CR4 read shadow: {:?}", error);
            return super::exception::handle_undefined_opcode_exception();
        }
        ExitType::IncrementRIP
    } else {
        log::error!("Unhandled CR access: cr={} type={}", cr_number, access_type);
        super::exception::handle_undefined_opcode_exception()
    }
}

fn read_gpr(regs: &GuestRegisters, index: u8) -> u64 {
    match index {
        0 => regs.rax,
        1 => regs.rcx,
        2 => regs.rdx,
        3 => regs.rbx,
        4 => regs.rsp,
        5 => regs.rbp,
        6 => regs.rsi,
        7 => regs.rdi,
        8 => regs.r8,
        9 => regs.r9,
        10 => regs.r10,
        11 => regs.r11,
        12 => regs.r12,
        13 => regs.r13,
        14 => regs.r14,
        15 => regs.r15,
        _ => 0,
    }
}
