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
const CR0_PE: u64 = 1 << 0;
const CR0_PG: u64 = 1 << 31;

#[derive(Debug, PartialEq, Eq)]
struct Cr0Update {
    guest_value: u64,
    shadow_value: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct Cr4Update {
    guest_value: u64,
    shadow_value: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Cr4WriteError {
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

    if cr_number == 3 && access_type == 1 {
        let cs_selector = match vmread_checked(vmcs::guest::CS_SELECTOR) {
            Ok(value) => value,
            Err(error) => {
                log::error!("Failed to read guest CS for CR3 store: {:?}", error);
                return super::exception::handle_undefined_opcode_exception();
            }
        };
        if cs_selector & 3 != 0 {
            EventInjection::vmentry_inject_gp(0);
            return ExitType::Continue;
        }

        let value = match vmread_checked(vmcs::guest::CR3) {
            Ok(value) => value,
            Err(error) => {
                log::error!("Failed to read guest CR3: {:?}", error);
                return super::exception::handle_undefined_opcode_exception();
            }
        };

        // VM-entry restores RSP from the VMCS rather than the assembly GPR
        // frame, so MOV RSP, CR3 must update both copies.
        if reg_index == 4 {
            if let Err(error) = vmwrite_checked(vmcs::guest::RSP, value) {
                log::error!("Failed to write guest RSP for CR3 store: {:?}", error);
                return super::exception::handle_undefined_opcode_exception();
            }
        }
        write_gpr(guest_registers, reg_index, value);
        ExitType::IncrementRIP
    } else if cr_number == 0 && access_type == 0 {
        let value = read_gpr(guest_registers, reg_index);
        let fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };
        let update = match sanitize_cr0_write(value, fixed0, fixed1) {
            Ok(update) => update,
            Err(error) => {
                log::debug!("Rejected guest CR0 write {:#x}: {:?}", value, error);
                EventInjection::vmentry_inject_gp(0);
                return ExitType::Continue;
            }
        };

        if let Err(error) = vmwrite_checked(vmcs::guest::CR0, update.guest_value) {
            log::error!("Failed to write guest CR0: {:?}", error);
            return super::exception::handle_undefined_opcode_exception();
        }
        if let Err(error) = vmwrite_checked(vmcs::control::CR0_READ_SHADOW, update.shadow_value) {
            log::error!("Failed to write CR0 read shadow: {:?}", error);
            return super::exception::handle_undefined_opcode_exception();
        }
        ExitType::IncrementRIP
    } else if cr_number == 4 && access_type == 0 {
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
    // In stealth mode, reject guest attempts to set VMXE — we advertise no VMX support.
    // Bare metal without VMX would #GP on setting this bit.
    if !super::cpuid::transparent_mode_enabled(option_env!("HV_TRANSPARENT"))
        && (requested_value & CR4_VMXE != 0)
    {
        return Err(Cr4WriteError::DisallowedFixed1Bits);
    }

    let guest_value = requested_value | fixed0;

    if guest_value & !fixed1 != 0 {
        return Err(Cr4WriteError::DisallowedFixed1Bits);
    }

    let shadow_value = if super::cpuid::transparent_mode_enabled(option_env!("HV_TRANSPARENT")) {
        guest_value
    } else {
        requested_value & !fixed0
    };

    Ok(Cr4Update {
        guest_value,
        shadow_value,
    })
}

fn sanitize_cr0_write(
    requested_value: u64,
    fixed0: u64,
    fixed1: u64,
) -> Result<Cr0Update, Cr4WriteError> {
    // Unrestricted guest relaxes only PE/PG. Every other fixed-zero bit must
    // remain materialized in the hardware CR0 while the shadow exposes the
    // value the guest actually requested.
    let forced = fixed0 & !(CR0_PE | CR0_PG);
    let guest_value = requested_value | forced;
    if guest_value & !fixed1 != 0 {
        return Err(Cr4WriteError::DisallowedFixed1Bits);
    }
    Ok(Cr0Update {
        guest_value,
        shadow_value: requested_value,
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

fn write_gpr(regs: &mut GuestRegisters, index: u8, value: u64) {
    match index {
        0 => regs.rax = value,
        1 => regs.rcx = value,
        2 => regs.rdx = value,
        3 => regs.rbx = value,
        4 => regs.rsp = value,
        5 => regs.rbp = value,
        6 => regs.rsi = value,
        7 => regs.rdi = value,
        8 => regs.r8 = value,
        9 => regs.r9 = value,
        10 => regs.r10 = value,
        11 => regs.r11 = value,
        12 => regs.r12 = value,
        13 => regs.r13 = value,
        14 => regs.r14 = value,
        15 => regs.r15 = value,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpr_writer_covers_all_cr3_store_destinations() {
        for index in 0..16 {
            let mut registers = GuestRegisters::default();
            let value = 0x1234_5678_9abc_def0 ^ index as u64;

            write_gpr(&mut registers, index, value);

            assert_eq!(read_gpr(&registers, index), value);
        }
    }

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
    fn cr4_write_rejects_guest_setting_vmxe() {
        const CR4_PAE: u64 = 1 << 5;
        let fixed0 = CR4_VMXE;
        let fixed1 = CR4_VMXE | CR4_PAE;

        assert!(sanitize_cr4_write(CR4_VMXE | CR4_PAE, fixed0, fixed1).is_err());
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

        let update = sanitize_cr4_write(0, fixed0, fixed1).unwrap();
        assert_eq!(update.guest_value, CR4_VMXE | CR4_PAE);
        assert_eq!(update.shadow_value, 0);
    }

    #[test]
    fn cr0_write_materializes_non_pe_pg_fixed_bits() {
        const CR0_NE: u64 = 1 << 5;
        const CR0_PE: u64 = 1;
        const CR0_PG: u64 = 1 << 31;
        let update = sanitize_cr0_write(CR0_PE | CR0_PG, CR0_NE, CR0_NE | CR0_PE | CR0_PG);

        let update = update.unwrap();
        assert_eq!(update.guest_value, CR0_PE | CR0_PG | CR0_NE);
        assert_eq!(update.shadow_value, CR0_PE | CR0_PG);
    }

    #[test]
    fn cr0_write_rejects_fixed_one_violation() {
        assert!(sanitize_cr0_write(1 << 63, 0, 0).is_err());
    }
}
