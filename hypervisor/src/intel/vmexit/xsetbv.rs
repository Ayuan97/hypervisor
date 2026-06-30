//! Provides handlers for managing VM exits due to the XSETBV instruction, ensuring
//! controlled manipulation of the XCR0 register by guest VMs.

use {
    crate::{
        intel::{events::EventInjection, support::vmread_checked, vmexit::ExitType},
        utils::capture::GuestRegisters,
        utils::instructions::xsetbv,
    },
    x86::{controlregs::Xcr0, vmx::vmcs},
};

const CR4_OSXSAVE: u64 = 1 << 18;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum XsetbvAction {
    Execute,
    GeneralProtection,
    UndefinedOpcode,
}

/// Manages the XSETBV instruction during a VM exit.
pub fn handle_xsetbv(guest_registers: &mut GuestRegisters) -> ExitType {
    let xcr = guest_registers.rcx as u32;
    let raw = (guest_registers.rax & 0xffff_ffff) | ((guest_registers.rdx & 0xffff_ffff) << 32);
    let guest_cpl = guest_cpl().unwrap_or(3);
    let guest_cr4 = guest_cr4().unwrap_or(0);

    // Reject bits the CPU doesn't support (CPUID leaf 0xD, subleaf 0)
    let supported = {
        let r = x86::cpuid::cpuid!(0xD, 0);
        (r.eax as u64) | ((r.edx as u64) << 32)
    };

    match classify_xsetbv_request(xcr, raw, supported, guest_cpl, guest_cr4) {
        XsetbvAction::Execute => {
            let value = Xcr0::from_bits_truncate(raw);
            xsetbv(value);

            ExitType::IncrementRIP
        }
        XsetbvAction::GeneralProtection => {
            EventInjection::vmentry_inject_gp(0);
            ExitType::Continue
        }
        XsetbvAction::UndefinedOpcode => {
            EventInjection::vmentry_inject_ud();
            ExitType::Continue
        }
    }
}

fn guest_cpl() -> Option<u16> {
    vmread_checked(vmcs::guest::CS_SELECTOR)
        .ok()
        .map(|selector| (selector & 0x3) as u16)
}

fn guest_cr4() -> Option<u64> {
    vmread_checked(vmcs::guest::CR4).ok()
}

fn classify_xsetbv_request(
    xcr: u32,
    raw: u64,
    supported: u64,
    guest_cpl: u16,
    guest_cr4: u64,
) -> XsetbvAction {
    if guest_cpl != 0 {
        return XsetbvAction::GeneralProtection;
    }

    if guest_cr4 & CR4_OSXSAVE == 0 {
        return XsetbvAction::UndefinedOpcode;
    }

    if xcr != 0 {
        return XsetbvAction::GeneralProtection;
    }

    // Bit 0 (x87) must always be set.
    if raw & 1 == 0 {
        return XsetbvAction::GeneralProtection;
    }

    // AVX (bit 2) requires SSE (bit 1).
    if raw & 0b100 != 0 && raw & 0b010 == 0 {
        return XsetbvAction::GeneralProtection;
    }

    if raw & !supported != 0 {
        return XsetbvAction::GeneralProtection;
    }

    XsetbvAction::Execute
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_mode_xsetbv_injects_general_protection() {
        assert_eq!(
            classify_xsetbv_request(0, 0b111, 0b111, 3, CR4_OSXSAVE),
            XsetbvAction::GeneralProtection
        );
    }

    #[test]
    fn xsetbv_without_osxsave_injects_undefined_opcode() {
        assert_eq!(
            classify_xsetbv_request(0, 0b111, 0b111, 0, 0),
            XsetbvAction::UndefinedOpcode
        );
    }

    #[test]
    fn ring0_supported_xcr0_update_executes() {
        assert_eq!(
            classify_xsetbv_request(0, 0b111, 0b111, 0, CR4_OSXSAVE),
            XsetbvAction::Execute
        );
    }

    #[test]
    fn unsupported_xcr_or_state_bits_inject_general_protection() {
        assert_eq!(
            classify_xsetbv_request(1, 0b111, 0b111, 0, CR4_OSXSAVE),
            XsetbvAction::GeneralProtection
        );
        assert_eq!(
            classify_xsetbv_request(0, 0b1000, 0b111, 0, CR4_OSXSAVE),
            XsetbvAction::GeneralProtection
        );
    }
}
