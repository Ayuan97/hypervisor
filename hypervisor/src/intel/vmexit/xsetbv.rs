//! Provides handlers for managing VM exits due to the XSETBV instruction, ensuring
//! controlled manipulation of the XCR0 register by guest VMs.

use {
    crate::{
        intel::{events::EventInjection, vmexit::ExitType},
        utils::capture::GuestRegisters,
        utils::instructions::{cr4, cr4_write, xsetbv},
    },
    x86::controlregs::{Cr4, Xcr0},
};

/// Manages the XSETBV instruction during a VM exit.
pub fn handle_xsetbv(guest_registers: &mut GuestRegisters) -> ExitType {
    let xcr = guest_registers.rcx as u32;
    if xcr != 0 {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    let raw = (guest_registers.rax & 0xffff_ffff) | ((guest_registers.rdx & 0xffff_ffff) << 32);

    // Bit 0 (x87) must always be set
    if raw & 1 == 0 {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // AVX (bit 2) requires SSE (bit 1)
    if raw & 0b100 != 0 && raw & 0b010 == 0 {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // Reject bits the CPU doesn't support (CPUID leaf 0xD, subleaf 0)
    let supported = {
        let r = x86::cpuid::cpuid!(0xD, 0);
        (r.eax as u64) | ((r.edx as u64) << 32)
    };
    if raw & !supported != 0 {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    let value = Xcr0::from_bits_truncate(raw);
    cr4_write(cr4() | Cr4::CR4_ENABLE_OS_XSAVE);
    xsetbv(value);

    ExitType::IncrementRIP
}
