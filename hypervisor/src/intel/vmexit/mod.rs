//! A module providing utilities and structures for handling VM exits.
//!
//! This module focuses on the reasons for VM exits, VM instruction errors, and the associated handlers for each exit type.
//! The handlers interpret and respond to different VM exit reasons, ensuring the safe and correct execution of the virtual machine.

use {
    super::{
        diag,
        support::{self, vmread_checked, vmwrite_checked},
        vcpu::Vcpu,
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
                invd::{handle_invd, handle_wbinvd_or_wbnoinvd},
                invept::handle_invept,
                invvpid::handle_invvpid,
                msr::{handle_msr_access, MsrAccessType},
                rdtsc::{handle_rdtsc, handle_rdtscp},
                vmcall::handle_vmcall,
                xsetbv::handle_xsetbv,
            },
            vmx::Vmx,
        },
        utils::{capture::GuestRegisters, instructions::cr3_write, processor::clear_virtualized},
    },
    x86::{
        dtables::{lgdt, lidt, DescriptorTablePointer},
        msr as x86_msr,
        vmx::vmcs::{guest, ro},
    },
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
#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
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
    ) -> Result<ExitType, HypervisorError> {
        log::debug!("Handling VMEXIT...");

        // Upon VM-exit, transfer the guest register values from VMCS to `self.registers` to ensure it reflects the latest and complete state.
        guest_registers.rip = vmread_checked(guest::RIP)?;
        guest_registers.rsp = vmread_checked(guest::RSP)?;
        guest_registers.rflags = vmread_checked(guest::RFLAGS)?;

        let exit_reason = vmread_checked(ro::EXIT_REASON)? as u32;
        let guest_cr3 = vmread_checked(guest::CR3).unwrap_or(0);
        let exit_qualification = vmread_checked(ro::EXIT_QUALIFICATION).unwrap_or(0);
        let breadcrumb_detail = vmexit_breadcrumb_detail(exit_reason, guest_registers);
        if vmexit_should_record_breadcrumb(exit_reason, guest_registers) {
            diag::record_current_vmexit(
                exit_reason as u64,
                guest_registers.rip,
                guest_registers.rsp,
                guest_cr3,
                guest_registers.rflags,
                exit_qualification,
                guest_registers.rax,
                guest_registers.rcx,
                guest_registers.rdx,
                breadcrumb_detail,
            );
        }

        crate::intel::diag_trace::trace_vmexit(exit_reason as u64, guest_registers.rip);

        let Some(basic_exit_reason) = decode_basic_exit_reason(exit_reason) else {
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

            reason if vmx_probe_instruction_should_inject_ud(reason) => {
                handle_undefined_opcode_exception()
            }

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
            VmxBasicExitReason::WbinvdOrWbnoinvd => handle_wbinvd_or_wbnoinvd(),
            VmxBasicExitReason::Rdtsc => handle_rdtsc(guest_registers, vmx),
            VmxBasicExitReason::Rdtscp => handle_rdtscp(guest_registers, vmx),
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

        if exit_type_advances_rip(exit_type) {
            self.advance_guest_rip(guest_registers)?;
        }

        if exit_type == ExitType::ExitHypervisor {
            self.leave_vmx_root(vmx)?;
            return Ok(exit_type);
        }

        super::host_idt::check_pending_nmi();

        log::debug!(
            "Guest registers after handling vmexit: {:#x?}",
            guest_registers
        );
        log::debug!("VMEXIT handled successfully.");

        Ok(exit_type)
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

    fn leave_vmx_root(&self, vmx: &Vmx) -> Result<(), HypervisorError> {
        let guest_state = GuestRootState::read_from_vmcs()?;

        if let Err(error) = Vcpu::invalidate_contexts() {
            log::error!("Context invalidation before VMXOFF failed: {:?}", error);
        }

        support::vmxoff()?;
        unsafe {
            guest_state.restore_after_vmxoff(vmx);
        }
        clear_virtualized();
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct GuestRootState {
    cr3: u64,
    fs_base: u64,
    gs_base: u64,
    gdtr_base: u64,
    gdtr_limit: u16,
    idtr_base: u64,
    idtr_limit: u16,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
}

impl GuestRootState {
    pub(crate) fn read_from_vmcs() -> Result<Self, HypervisorError> {
        Ok(Self {
            cr3: vmread_checked(guest::CR3)?,
            fs_base: vmread_checked(guest::FS_BASE)?,
            gs_base: vmread_checked(guest::GS_BASE)?,
            gdtr_base: vmread_checked(guest::GDTR_BASE)?,
            gdtr_limit: vmread_checked(guest::GDTR_LIMIT)? as u16,
            idtr_base: vmread_checked(guest::IDTR_BASE)?,
            idtr_limit: vmread_checked(guest::IDTR_LIMIT)? as u16,
            sysenter_cs: vmread_checked(guest::IA32_SYSENTER_CS)?,
            sysenter_esp: vmread_checked(guest::IA32_SYSENTER_ESP)?,
            sysenter_eip: vmread_checked(guest::IA32_SYSENTER_EIP)?,
        })
    }

    pub(crate) unsafe fn restore_after_vmxoff(&self, vmx: &Vmx) {
        vmx.restore_control_registers();
        x86_msr::wrmsr(x86_msr::IA32_FS_BASE, self.fs_base);
        x86_msr::wrmsr(x86_msr::IA32_GS_BASE, self.gs_base);
        x86_msr::wrmsr(x86_msr::IA32_SYSENTER_CS, self.sysenter_cs);
        x86_msr::wrmsr(x86_msr::IA32_SYSENTER_ESP, self.sysenter_esp);
        x86_msr::wrmsr(x86_msr::IA32_SYSENTER_EIP, self.sysenter_eip);

        let gdtr = DescriptorTablePointer::<u64> {
            limit: self.gdtr_limit,
            base: self.gdtr_base as *const u64,
        };
        let idtr = DescriptorTablePointer::<u64> {
            limit: self.idtr_limit,
            base: self.idtr_base as *const u64,
        };
        lgdt(&gdtr);
        lidt(&idtr);
        cr3_write(self.cr3);
    }
}

fn exit_type_advances_rip(exit_type: ExitType) -> bool {
    matches!(exit_type, ExitType::IncrementRIP | ExitType::ExitHypervisor)
}

fn vmx_probe_instruction_should_inject_ud(reason: VmxBasicExitReason) -> bool {
    matches!(
        reason,
        VmxBasicExitReason::Getsec
            | VmxBasicExitReason::Encls
            | VmxBasicExitReason::Enclv
            | VmxBasicExitReason::Vmclear
            | VmxBasicExitReason::Vmlaunch
            | VmxBasicExitReason::Vmptrld
            | VmxBasicExitReason::Vmptrst
            | VmxBasicExitReason::Vmread
            | VmxBasicExitReason::Vmresume
            | VmxBasicExitReason::Vmwrite
            | VmxBasicExitReason::Vmxon
            | VmxBasicExitReason::Vmxoff
    )
}

fn decode_basic_exit_reason(raw_exit_reason: u32) -> Option<VmxBasicExitReason> {
    VmxBasicExitReason::from_u32(raw_exit_reason & 0xffff)
}

fn vmexit_should_record_breadcrumb(exit_reason: u32, _guest_registers: &GuestRegisters) -> bool {
    !matches!(
        decode_basic_exit_reason(exit_reason),
        Some(
            VmxBasicExitReason::Cpuid
                | VmxBasicExitReason::Rdmsr
                | VmxBasicExitReason::Wrmsr
                | VmxBasicExitReason::Rdtsc
                | VmxBasicExitReason::Rdtscp
                | VmxBasicExitReason::ExternalInterrupt
                | VmxBasicExitReason::MonitorTrapFlag
        )
    )
}

fn vmexit_breadcrumb_detail(exit_reason: u32, guest_registers: &GuestRegisters) -> u64 {
    match decode_basic_exit_reason(exit_reason) {
        Some(VmxBasicExitReason::Cpuid) => {
            ((guest_registers.rcx as u32 as u64) << 32) | guest_registers.rax as u32 as u64
        }
        Some(VmxBasicExitReason::Rdmsr) | Some(VmxBasicExitReason::Wrmsr) => guest_registers.rcx,
        Some(VmxBasicExitReason::ExceptionOrNmi) => {
            vmread_checked(ro::VMEXIT_INTERRUPTION_INFO).unwrap_or(0)
        }
        Some(VmxBasicExitReason::EptViolation) | Some(VmxBasicExitReason::EptMisconfiguration) => {
            vmread_checked(ro::GUEST_PHYSICAL_ADDR_FULL).unwrap_or(0)
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_vmx_probe_instructions_inject_ud() {
        assert!(vmx_probe_instruction_should_inject_ud(
            VmxBasicExitReason::Vmread
        ));
        assert!(vmx_probe_instruction_should_inject_ud(
            VmxBasicExitReason::Vmwrite
        ));
        assert!(vmx_probe_instruction_should_inject_ud(
            VmxBasicExitReason::Vmclear
        ));
        assert!(!vmx_probe_instruction_should_inject_ud(
            VmxBasicExitReason::Cpuid
        ));
    }

    #[test]
    fn sgx_instruction_exits_inject_ud() {
        assert!(vmx_probe_instruction_should_inject_ud(
            VmxBasicExitReason::Encls
        ));
        assert!(vmx_probe_instruction_should_inject_ud(
            VmxBasicExitReason::Enclv
        ));
    }

    #[test]
    fn raw_exit_reason_decoding_ignores_non_basic_flags() {
        let raw = 0x8000_0000 | VmxBasicExitReason::Cpuid as u32;

        assert_eq!(
            decode_basic_exit_reason(raw),
            Some(VmxBasicExitReason::Cpuid)
        );
    }

    #[test]
    fn breadcrumb_skips_high_frequency_exit_reasons() {
        let regs = GuestRegisters::default();

        assert!(!vmexit_should_record_breadcrumb(
            VmxBasicExitReason::Cpuid as u32,
            &regs
        ));
        assert!(!vmexit_should_record_breadcrumb(
            VmxBasicExitReason::Rdmsr as u32,
            &regs
        ));
        assert!(!vmexit_should_record_breadcrumb(
            VmxBasicExitReason::Rdtsc as u32,
            &regs
        ));
        assert!(!vmexit_should_record_breadcrumb(
            VmxBasicExitReason::ExternalInterrupt as u32,
            &regs
        ));
        assert!(vmexit_should_record_breadcrumb(
            VmxBasicExitReason::EptViolation as u32,
            &regs
        ));
        assert!(vmexit_should_record_breadcrumb(
            VmxBasicExitReason::Vmcall as u32,
            &regs
        ));
    }

    #[test]
    fn cpuid_breadcrumb_detail_packs_leaf_and_subleaf() {
        let mut regs = GuestRegisters::default();
        regs.rax = 0x12;
        regs.rcx = 0x34;

        assert_eq!(
            vmexit_breadcrumb_detail(VmxBasicExitReason::Cpuid as u32, &regs),
            0x34_0000_0012
        );
    }

    #[test]
    fn msr_breadcrumb_detail_records_msr_index() {
        let mut regs = GuestRegisters::default();
        regs.rcx = 0x570;

        assert_eq!(
            vmexit_breadcrumb_detail(VmxBasicExitReason::Rdmsr as u32, &regs),
            0x570
        );
    }
}
