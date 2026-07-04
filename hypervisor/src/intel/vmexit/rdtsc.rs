//! Handles RDTSC virtualization tasks, specifically intercepting and managing
//! the `RDTSC` (Read Time-Stamp Counter) instruction in a VM to ensure appropriate time
//! information is provided to the guest while maintaining the integrity of the hypervisor.

use {
    crate::{intel::vmexit::ExitType, utils::capture::GuestRegisters},
    x86::time::{rdtsc, rdtscp},
};

/*
User can add the following later:
- https://secret.club/2020/01/12/battleye-hypervisor-detection.html
- https://github.com/not-matthias/rdtsc_bench/blob/main/src/main.rs
*/

/// Handles the `RDTSC` VM-exit.
///
/// This function is invoked when the guest executes the `RDTSC` instruction.
/// It reads the current value of the host's time-stamp counter and updates the guest's
/// RAX and RDX registers with the low and high 32-bits of the counter, respectively.
///
/// # Arguments
///
/// * `guest_registers` - A mutable reference to the guest's current register state.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `RDTSC` instruction in the VM.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual, Table C-1. Basic Exit Reasons 10.
pub fn handle_rdtsc(
    guest_registers: &mut GuestRegisters,
    vmx: &mut crate::intel::vmx::Vmx,
) -> ExitType {
    if vmx.cpuid_entry_tsc != 0 {
        handle_rdtsc_spoofed(guest_registers, vmx)
    } else {
        handle_rdtsc_with_offset(guest_registers, || unsafe { rdtsc() }, vmx.tsc_offset)
    }
}

pub fn handle_rdtscp(
    guest_registers: &mut GuestRegisters,
    vmx: &mut crate::intel::vmx::Vmx,
) -> ExitType {
    if vmx.cpuid_entry_tsc != 0 {
        let (_, aux) = unsafe { rdtscp() };
        guest_registers.rcx = aux as u64;
        handle_rdtsc_spoofed(guest_registers, vmx)
    } else {
        handle_rdtscp_with_offset(guest_registers, || unsafe { rdtscp() }, vmx.tsc_offset)
    }
}

pub const SPOOF_WINDOW: u64 = 10_000;

fn handle_rdtsc_spoofed(
    guest_registers: &mut GuestRegisters,
    vmx: &mut crate::intel::vmx::Vmx,
) -> ExitType {
    use super::cpuid::{CPUID_BARE_METAL_COST, VMEXIT_ENTRY_OVERHEAD};
    let now = unsafe { x86::time::rdtsc() };
    let elapsed = now.wrapping_sub(vmx.cpuid_entry_tsc);
    vmx.cpuid_entry_tsc = 0;
    super::cpuid::disable_rdtsc_exiting();
    if elapsed > SPOOF_WINDOW {
        write_tsc(guest_registers, now.wrapping_add(vmx.tsc_offset));
        return ExitType::IncrementRIP;
    }
    let vmcs_tsc_offset =
        crate::intel::support::vmread_checked(x86::vmx::vmcs::control::TSC_OFFSET_FULL)
            .unwrap_or(0);
    // cpuid_entry_tsc was captured AFTER VM-exit transition (~600 cycles).
    // Subtract VMEXIT_ENTRY_OVERHEAD to approximate guest-side TSC at CPUID time,
    // then add bare-metal CPUID cost so guest sees: rdtsc_after - rdtsc_before ≈ 120.
    let spoofed = now
        .wrapping_sub(elapsed)
        .wrapping_sub(VMEXIT_ENTRY_OVERHEAD)
        .wrapping_add(CPUID_BARE_METAL_COST)
        .wrapping_add(vmcs_tsc_offset);
    write_tsc(guest_registers, spoofed);
    ExitType::IncrementRIP
}

fn handle_rdtsc_with_offset<F>(
    guest_registers: &mut GuestRegisters,
    read_timestamp: F,
    tsc_offset: u64,
) -> ExitType
where
    F: FnOnce() -> u64,
{
    write_tsc(guest_registers, read_timestamp().wrapping_add(tsc_offset));
    ExitType::IncrementRIP
}

fn handle_rdtscp_with_offset<F>(
    guest_registers: &mut GuestRegisters,
    read_timestamp: F,
    tsc_offset: u64,
) -> ExitType
where
    F: FnOnce() -> (u64, u32),
{
    let (rdtscp_value, tsc_aux) = read_timestamp();
    write_tsc(guest_registers, rdtscp_value.wrapping_add(tsc_offset));
    guest_registers.rcx = tsc_aux as u64;

    ExitType::IncrementRIP
}

fn write_tsc(guest_registers: &mut GuestRegisters, tsc_value: u64) {
    guest_registers.rax = tsc_value & 0xFFFF_FFFF;
    guest_registers.rdx = tsc_value >> 32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdtsc_exit_returns_tsc_with_guest_offset() {
        let mut regs = GuestRegisters::default();

        assert!(matches!(
            handle_rdtsc_with_offset(&mut regs, || 0x1_0000_0010, u64::MAX - 0x0f),
            ExitType::IncrementRIP
        ));
        assert_eq!(regs.rax, 0);
        assert_eq!(regs.rdx, 1);
    }

    #[test]
    fn rdtscp_exit_returns_tsc_with_guest_offset_and_aux() {
        let mut regs = GuestRegisters::default();

        assert!(matches!(
            handle_rdtscp_with_offset(&mut regs, || (0x1_0000_0010, 0x99aa_bbcc), u64::MAX - 0x0f),
            ExitType::IncrementRIP
        ));
        assert_eq!(regs.rax, 0);
        assert_eq!(regs.rdx, 1);
        assert_eq!(regs.rcx, 0x99aa_bbcc);
    }

    #[test]
    fn rdtscp_exit_returns_tsc_and_aux_and_advances_rip() {
        let mut regs = GuestRegisters::default();

        assert!(matches!(
            handle_rdtscp_with_offset(&mut regs, || (0x1122_3344_5566_7788, 0x99aa_bbcc), 0),
            ExitType::IncrementRIP
        ));
        assert_eq!(regs.rax, 0x5566_7788);
        assert_eq!(regs.rdx, 0x1122_3344);
        assert_eq!(regs.rcx, 0x99aa_bbcc);
    }
}
