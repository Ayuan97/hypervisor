//! Provides virtual machine management capabilities, specifically for handling MSR
//! read and write operations. It ensures that guest MSR accesses are properly
//! intercepted and handled, with support for injecting faults for unauthorized accesses.

use crate::{
    intel::{events::EventInjection, vmexit::ExitType},
    utils::capture::GuestRegisters,
};

/// Enum representing the type of MSR access.
///
/// There are two types of MSR access: reading from an MSR and writing to an MSR.
pub enum MsrAccessType {
    Read,
    Write,
}

/// Handles MSR access VM exits.
///
/// MSR bitmap is all-zeros, so MSRs in 0x0-0x1FFF and 0xC0000000-0xC0001FFF
/// pass through without VM exit. Only out-of-range MSRs reach here (Intel SDM
/// 25.1.3). Native rdmsr/wrmsr in VMX root for non-existent MSRs → #GP → BSOD.
/// Reads: return 0 and advance RIP (fast path, avoids #GP exception overhead).
/// Writes: inject #GP (can't silently discard writes).
pub fn handle_msr_access(
    guest_registers: &mut GuestRegisters,
    access_type: MsrAccessType,
) -> ExitType {
    match access_type {
        MsrAccessType::Read => {
            guest_registers.rax = 0;
            guest_registers.rdx = 0;
            ExitType::IncrementRIP
        }
        MsrAccessType::Write => {
            EventInjection::vmentry_inject_gp(0);
            ExitType::Continue
        }
    }
}
