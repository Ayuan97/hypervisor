use {
    crate::{
        intel::{
            events::EventInjection,
            support::{vmread_checked, vmwrite_checked},
            vmexit::ExitType,
        },
        utils::capture::GuestRegisters,
    },
    x86::{msr, vmx::vmcs},
};

const CR4_VMXE: u64 = 1 << 13;

#[derive(Debug, PartialEq, Eq)]
struct Cr4Update {
    guest_value: u64,
    shadow_value: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Cr4WriteError {
    MissingFixed0Bits,
    DisallowedFixed1Bits,
}

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
        let fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };
        let update = match sanitize_cr4_write(value, fixed0, fixed1) {
            Ok(update) => update,
            Err(error) => {
                log::debug!("Rejected guest CR4 write {:#x}: {:?}", value, error);
                EventInjection::vmentry_inject_gp(0);
                return ExitType::Continue;
            }
        };

        if let Err(error) = vmwrite_checked(vmcs::guest::CR4, update.guest_value) {
            log::error!("Failed to write guest CR4: {:?}", error);
            return super::exception::handle_undefined_opcode_exception();
        }
        if let Err(error) = vmwrite_checked(vmcs::control::CR4_READ_SHADOW, update.shadow_value) {
            log::error!("Failed to write CR4 read shadow: {:?}", error);
            return super::exception::handle_undefined_opcode_exception();
        }
        ExitType::IncrementRIP
    } else {
        log::error!("Unhandled CR access: cr={} type={}", cr_number, access_type);
        super::exception::handle_undefined_opcode_exception()
    }
}

fn sanitize_cr4_write(
    requested_value: u64,
    fixed0: u64,
    fixed1: u64,
) -> Result<Cr4Update, Cr4WriteError> {
    let guest_value = requested_value | CR4_VMXE;

    if guest_value & fixed0 != fixed0 {
        return Err(Cr4WriteError::MissingFixed0Bits);
    }
    if guest_value & !fixed1 != 0 {
        return Err(Cr4WriteError::DisallowedFixed1Bits);
    }

    let shadow_value = if option_env!("HV_TRANSPARENT").is_some() {
        guest_value
    } else {
        requested_value & !CR4_VMXE
    };

    Ok(Cr4Update {
        guest_value,
        shadow_value,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr4_write_keeps_vmxe_set_but_hidden_in_shadow() {
        const CR4_PAE: u64 = 1 << 5;
        let fixed0 = CR4_VMXE;
        let fixed1 = CR4_VMXE | CR4_PAE;

        let update = sanitize_cr4_write(CR4_PAE, fixed0, fixed1).unwrap();

        assert_eq!(update.guest_value, CR4_VMXE | CR4_PAE);
        assert_eq!(update.shadow_value, CR4_PAE);
    }

    #[test]
    fn cr4_write_rejects_bits_disallowed_by_vmx_fixed1() {
        let fixed0 = CR4_VMXE;
        let fixed1 = CR4_VMXE;

        assert!(sanitize_cr4_write(1 << 63, fixed0, fixed1).is_err());
    }

    #[test]
    fn cr4_write_rejects_missing_vmx_fixed0_bits() {
        const CR4_PAE: u64 = 1 << 5;
        let fixed0 = CR4_VMXE | CR4_PAE;
        let fixed1 = CR4_VMXE | CR4_PAE;

        assert!(sanitize_cr4_write(0, fixed0, fixed1).is_err());
    }
}
