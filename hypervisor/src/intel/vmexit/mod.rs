//! A module providing utilities and structures for handling VM exits.
//!
//! This module focuses on the reasons for VM exits, VM instruction errors, and the associated handlers for each exit type.
//! The handlers interpret and respond to different VM exit reasons, ensuring the safe and correct execution of the virtual machine.

use {
    super::{
        diag,
        support::{vmread_checked, vmwrite_checked},
        vmerror::VmxBasicExitReason,
    },
    crate::{
        error::HypervisorError,
        intel::{
            vmexit::{
                cpuid::handle_cpuid,
                cr::handle_cr_access,
                ept::{handle_ept_misconfiguration, handle_ept_violation, handle_mtf},
                exception::{handle_exception, handle_undefined_opcode_exception},
                invd::handle_invd,
                invept::handle_invept,
                invvpid::handle_invvpid,
                msr::{handle_msr_access, MsrAccessType},
                rdtsc::handle_rdtsc,
                vmcall::handle_vmcall,
                xsetbv::handle_xsetbv,
            },
            vmx::Vmx,
        },
        utils::capture::GuestRegisters,
    },
    x86::vmx::vmcs::{guest, ro},
};

pub mod cpuid;
pub mod cr;
pub mod ept;
pub mod exception;
pub mod invd;
pub mod invept;
pub mod invvpid;
pub mod msr;
pub mod rdtsc;
pub mod vmcall;
pub mod xsetbv;

/// Represents the type of VM exit.
#[derive(PartialOrd, PartialEq)]
pub enum ExitType {
    ExitHypervisor,
    IncrementRIP,
    Continue,
}

pub struct VmExit;

impl VmExit {
    pub fn new() -> Self {
        Self
    }

    /// Handles the VM-exit.
    ///
    /// This function interprets the VM exit reason and invokes the appropriate handler based on the exit type.
    ///
    /// # Arguments
    ///
    /// * `registers` - A mutable reference to the guest's current register state.
    ///
    /// # Returns
    ///
    /// A result containing the VM exit reason if the handling was successful or an error if the VM exit reason is unknown or unsupported.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.9 VM-EXIT INFORMATION FIELDS
    /// - APPENDIX C VMX BASIC EXIT REASONS
    /// - Table C-1. Basic Exit Reasons
    pub fn handle_vmexit(
        &self,
        guest_registers: &mut GuestRegisters,
        vmx: &mut Vmx,
    ) -> Result<(), HypervisorError> {
        log::debug!("Handling VMEXIT...");

        // Upon VM-exit, transfer the guest register values from VMCS to `self.registers` to ensure it reflects the latest and complete state.
        guest_registers.rip = vmread_checked(guest::RIP)?;
        guest_registers.rsp = vmread_checked(guest::RSP)?;
        guest_registers.rflags = vmread_checked(guest::RFLAGS)?;

        let exit_reason = vmread_checked(ro::EXIT_REASON)? as u32;

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            log::error!("Unknown exit reason: {:#x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };

        log::debug!("Basic Exit Reason: {}", basic_exit_reason);

        log::debug!(
            "Guest Registers before handling vmexit: {:#x?}",
            guest_registers
        );

        // Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.2 Instructions That Cause VM Exits Unconditionally:
        // - The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC, INVD, and XSETBV.
        // - This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //
        // 26.1.3 Instructions That Cause VM Exits Conditionally: Certain instructions cause VM exits in VMX non-root operation depending on the setting of the VM-execution controls.
        use core::sync::atomic::Ordering::Relaxed;
        diag::EXIT_TOTAL.fetch_add(1, Relaxed);
        diag::LAST_EXIT_REASON.store(exit_reason as u64, Relaxed);

        let exit_type = match basic_exit_reason {
            VmxBasicExitReason::ExceptionOrNmi => {
                diag::EXIT_EXCEPTION.fetch_add(1, Relaxed);
                handle_exception(guest_registers, vmx)
            }
            VmxBasicExitReason::ExternalInterrupt => {
                diag::EXIT_EXT_INT.fetch_add(1, Relaxed);
                ExitType::Continue
            }
            VmxBasicExitReason::Cpuid => {
                diag::EXIT_CPUID.fetch_add(1, Relaxed);
                handle_cpuid(guest_registers, vmx)
            }

            VmxBasicExitReason::Vmcall => match handle_vmcall(guest_registers, vmx) {
                Some(exit) => exit,
                None => handle_undefined_opcode_exception(),
            },

            VmxBasicExitReason::ControlRegisterAccesses => {
                diag::EXIT_CR_ACCESS.fetch_add(1, Relaxed);
                handle_cr_access(guest_registers)
            }

            VmxBasicExitReason::Getsec
            | VmxBasicExitReason::Vmclear
            | VmxBasicExitReason::Vmlaunch
            | VmxBasicExitReason::Vmptrld
            | VmxBasicExitReason::Vmptrst
            | VmxBasicExitReason::Vmresume
            | VmxBasicExitReason::Vmxon
            | VmxBasicExitReason::Vmxoff => handle_undefined_opcode_exception(),

            VmxBasicExitReason::MonitorTrapFlag => handle_mtf(vmx),

            VmxBasicExitReason::Rdmsr => {
                diag::EXIT_MSR.fetch_add(1, Relaxed);
                handle_msr_access(guest_registers, MsrAccessType::Read)
            }
            VmxBasicExitReason::Wrmsr => {
                diag::EXIT_MSR.fetch_add(1, Relaxed);
                handle_msr_access(guest_registers, MsrAccessType::Write)
            }
            VmxBasicExitReason::Invd => handle_invd(guest_registers),
            VmxBasicExitReason::Rdtsc => handle_rdtsc(guest_registers),
            VmxBasicExitReason::EptViolation => {
                diag::EXIT_EPT_VIOLATION.fetch_add(1, Relaxed);
                handle_ept_violation(guest_registers, vmx)
            }
            VmxBasicExitReason::EptMisconfiguration => {
                diag::EXIT_EPT_MISCONFIG.fetch_add(1, Relaxed);
                handle_ept_misconfiguration()
            }
            VmxBasicExitReason::Invept => handle_invept(),
            VmxBasicExitReason::Invvpid => handle_invvpid(),
            VmxBasicExitReason::Xsetbv => {
                diag::EXIT_XSETBV.fetch_add(1, Relaxed);
                handle_xsetbv(guest_registers)
            }
            _ => {
                diag::EXIT_OTHER.fetch_add(1, Relaxed);
                log::error!("Unhandled VM exit reason: {}", basic_exit_reason);
                handle_undefined_opcode_exception()
            }
        };

        if exit_type == ExitType::IncrementRIP {
            self.advance_guest_rip(guest_registers)?;
        }

        super::host_idt::check_pending_nmi();

        log::debug!(
            "Guest registers after handling vmexit: {:#x?}",
            guest_registers
        );
        log::debug!("VMEXIT handled successfully.");

        return Ok(());
    }

    /// Advances the guest's instruction pointer (RIP) after a VM exit.
    ///
    /// When a VM exit occurs, the guest's execution is interrupted, and control is transferred
    /// to the hypervisor. To ensure that the guest does not re-execute the instruction that
    /// caused the VM exit, the hypervisor needs to advance the guest's RIP to the next instruction.
    #[rustfmt::skip]
    fn advance_guest_rip(&self, guest_registers: &mut GuestRegisters) -> Result<(), HypervisorError> {
        log::trace!("Advancing guest RIP...");
        let len = vmread_checked(ro::VMEXIT_INSTRUCTION_LEN)?;
        guest_registers.rip += len;
        vmwrite_checked(guest::RIP, guest_registers.rip)?;
        log::trace!("Guest RIP advanced to: {:#x}", guest_registers.rip);
        Ok(())
    }
}
