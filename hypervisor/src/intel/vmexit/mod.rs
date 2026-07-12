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
pub mod idle;
pub mod invd;
pub mod invept;
pub mod invvpid;
pub mod msr;
pub mod rdtsc;
pub mod vmcall;
pub mod xsetbv;

static BUGCHECK_BAILOUT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Represents the type of VM exit.
#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum ExitType {
    ExitHypervisor,
    IncrementRIP,
    Continue,
}

/// Re-inject any event that was being delivered through the guest IDT when this
/// VM-exit occurred.  If the valid bit in IDT_VECTORING_INFO is set, the CPU
/// was mid-delivery of an interrupt/exception and that event was lost.  We copy
/// it into VMENTRY_INTERRUPTION_INFO so the CPU re-delivers it on vmresume.
/// Without this, timer interrupts (and others) can be silently dropped during
/// heavy VM-exit traffic, stalling the guest scheduler → system freeze.
#[inline]
fn reinject_idt_vectoring_event() {
    let vectoring_info = vmread_checked(ro::IDT_VECTORING_INFO).unwrap_or(0);
    if vectoring_info & (1 << 31) != 0 {
        let _ = vmwrite_checked(
            x86::vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
            vectoring_info,
        );
        let event_type = (vectoring_info >> 8) & 0x7;
        let has_error_code = (vectoring_info >> 11) & 1 != 0;
        if has_error_code {
            let error_code = vmread_checked(ro::IDT_VECTORING_ERR_CODE).unwrap_or(0);
            let _ = vmwrite_checked(
                x86::vmx::vmcs::control::VMENTRY_EXCEPTION_ERR_CODE,
                error_code,
            );
        }
        if event_type == 4 || event_type == 6 {
            let instr_len = vmread_checked(ro::VMEXIT_INSTRUCTION_LEN).unwrap_or(0);
            if instr_len != 0 {
                let _ = vmwrite_checked(
                    x86::vmx::vmcs::control::VMENTRY_INSTRUCTION_LEN,
                    instr_len,
                );
            }
        }
    }
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
        let exit_tsc_start = unsafe { x86::time::rdtsc() };

        // Snapshot + freeze the LBR stack ASAP so host handler branches do
        // not pollute what the guest reads back later. Cheap fast-path if
        // LBR is disabled (single RDMSR). See intel/lbr.rs.
        let lbr_saved = crate::intel::lbr::save_and_disable_lbr();

        let exit_reason = vmread_checked(ro::EXIT_REASON)? as u32;
        diag::watchdog_handler_start(exit_tsc_start, exit_reason as u64);
        let vm_entry_failure = (exit_reason & 0x8000_0000) != 0;
        let basic_reason = exit_reason & 0xFFFF;

        if vm_entry_failure {
            use core::sync::atomic::Ordering::Relaxed;
            diag::EXIT_OTHER.fetch_add(1, Relaxed);
            diag::LAST_HANDLER_ID.store(200, Relaxed);
            diag::LAST_HANDLER_DETAIL.store(exit_reason as u64, Relaxed);
            let guest_rip = vmread_checked(guest::RIP).unwrap_or(0);
            let exit_qual = vmread_checked(ro::EXIT_QUALIFICATION).unwrap_or(0);
            diag::ring_record(exit_reason as u64, guest_rip, exit_qual, 0xDEAD_E0);
            log::error!(
                "VM-entry failure: reason={:#x} qual={:#x} rip={:#x} — halting CPU",
                exit_reason, exit_qual, guest_rip
            );
            crate::intel::vmlaunch::fatal_vmx_failure_loop_pub();
        }

        // ── Fast path: CPUID / RDTSC / RDTSCP ──
        // The slow path bumps EXIT_TOTAL / per-reason counters after
        // decoding — fast paths skip that block, so they used to be
        // invisible to `GET_COUNTER` and the freeze/watchdog logic.
        // Bump the matching counters here so diagnostics stay honest.
        use core::sync::atomic::Ordering::Relaxed;
        if basic_reason == 10
        /* CPUID */
        {
            diag::EXIT_TOTAL.fetch_add(1, Relaxed);
            diag::EXIT_CPUID.fetch_add(1, Relaxed);
            diag::LAST_EXIT_REASON.store(exit_reason as u64, Relaxed);
            diag::cpu_enter_phase(diag::PHASE_FAST_CPUID);
            guest_registers.rip = vmread_checked(guest::RIP)?;
            diag::observe_guest_rip_for_bugcheck(guest_registers.rip, guest_registers.rcx);
            diag::cpu_enter_phase(diag::PHASE_FAST_CPUID_DONE);
            let exit_type = handle_cpuid(guest_registers, vmx, exit_tsc_start);
            diag::cpu_enter_phase(diag::PHASE_FAST_RIP_ADV);
            if exit_type_advances_rip(exit_type) {
                self.advance_guest_rip(guest_registers)?;
            }
            // `handle_cpuid` can dispatch the diag-channel VMCALL commands via
            // `dispatch_command`, including CMD_DEVIRTUALIZE which returns
            // ExitHypervisor. The fast path used to skip `leave_vmx_root()`
            // entirely, so the `launch_vm` return stub would assume VMXOFF had
            // already run and would crash. Handle it here to keep parity with
            // the slow path.
            if exit_type == ExitType::ExitHypervisor {
                // Fast path skipped populating rsp/rflags in guest_registers
                // (only rip was read above). vmexit_devirtualize_restore uses
                // both to build the IRET-like frame on the guest stack — if
                // they are stale, the frame lands at a garbage address and
                // the returning function trips Windows FAST_FAIL_INCORRECT_
                // STACK (BSOD 0x139/0x04). Populate them here before we bail.
                guest_registers.rsp = vmread_checked(guest::RSP)?;
                guest_registers.rflags = vmread_checked(guest::RFLAGS)?;
                if lbr_saved {
                    crate::intel::lbr::restore_lbr();
                }
                self.leave_vmx_root(vmx)?;
                return Ok(exit_type);
            }
            reinject_idt_vectoring_event();
            super::host_idt::check_pending_nmi();
            diag::cpu_enter_phase(diag::PHASE_PRE_VMRESUME);
            diag::watchdog_handler_finish(guest_registers.rip);
            if lbr_saved {
                crate::intel::lbr::restore_lbr();
            }
            return Ok(exit_type);
        }
        if basic_reason == 16
        /* RDTSC */
        {
            diag::EXIT_TOTAL.fetch_add(1, Relaxed);
            diag::EXIT_RDTSC.fetch_add(1, Relaxed);
            diag::LAST_EXIT_REASON.store(exit_reason as u64, Relaxed);
            guest_registers.rip = vmread_checked(guest::RIP)?;
            diag::observe_guest_rip_for_bugcheck(guest_registers.rip, guest_registers.rcx);
            let exit_type = handle_rdtsc(guest_registers, vmx);
            if exit_type_advances_rip(exit_type) {
                self.advance_guest_rip(guest_registers)?;
            }
            reinject_idt_vectoring_event();
            super::host_idt::check_pending_nmi();
            diag::watchdog_handler_finish(guest_registers.rip);
            if lbr_saved {
                crate::intel::lbr::restore_lbr();
            }
            return Ok(exit_type);
        }
        if basic_reason == 51
        /* RDTSCP */
        {
            diag::EXIT_TOTAL.fetch_add(1, Relaxed);
            diag::EXIT_RDTSC.fetch_add(1, Relaxed);
            diag::LAST_EXIT_REASON.store(exit_reason as u64, Relaxed);
            guest_registers.rip = vmread_checked(guest::RIP)?;
            diag::observe_guest_rip_for_bugcheck(guest_registers.rip, guest_registers.rcx);
            let exit_type = handle_rdtscp(guest_registers, vmx);
            if exit_type_advances_rip(exit_type) {
                self.advance_guest_rip(guest_registers)?;
            }
            reinject_idt_vectoring_event();
            super::host_idt::check_pending_nmi();
            diag::watchdog_handler_finish(guest_registers.rip);
            if lbr_saved {
                crate::intel::lbr::restore_lbr();
            }
            return Ok(exit_type);
        }

        // ── Slow path: all other exits ──

        diag::cpu_enter_phase(diag::PHASE_SLOW_PATH);
        // Disarm RDTSC trap if it was armed by a prior CPUID exit.
        if vmx.cpuid_entry_tsc != 0 {
            vmx.cpuid_entry_tsc = 0;
            cpuid::disable_rdtsc_exiting();
        }

        guest_registers.rip = vmread_checked(guest::RIP)?;
        guest_registers.rsp = vmread_checked(guest::RSP)?;
        guest_registers.rflags = vmread_checked(guest::RFLAGS)?;
        diag::observe_guest_rip_for_bugcheck(guest_registers.rip, guest_registers.rcx);

        let exit_qualification = vmread_checked(ro::EXIT_QUALIFICATION).unwrap_or(0);

        diag::ring_record(
            exit_reason as u64,
            guest_registers.rip,
            exit_qualification,
            guest_registers.rax,
        );

        let guest_cr3 = vmread_checked(guest::CR3).unwrap_or(0);
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

        // `Relaxed` is already imported at the top of the function for the
        // fast-path counters; don't re-import at the slow-path scope.
        diag::EXIT_TOTAL.fetch_add(1, Relaxed);
        diag::LAST_EXIT_REASON.store(exit_reason as u64, Relaxed);

        diag::cpu_enter_phase(diag::PHASE_SLOW_HANDLER);
        let exit_type = match basic_exit_reason {
            VmxBasicExitReason::ExceptionOrNmi => {
                diag::EXIT_EXCEPTION.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(1, Relaxed);
                handle_exception(guest_registers, vmx)
            }
            VmxBasicExitReason::ExternalInterrupt => {
                diag::EXIT_EXT_INT.fetch_add(1, Relaxed);
                ExitType::Continue
            }
            VmxBasicExitReason::Cpuid => {
                diag::EXIT_CPUID.fetch_add(1, Relaxed);
                handle_cpuid(guest_registers, vmx, exit_tsc_start)
            }

            VmxBasicExitReason::Vmcall => {
                diag::LAST_HANDLER_ID.store(4, Relaxed);
                match handle_vmcall(guest_registers, vmx) {
                    Some(exit) => exit,
                    None => handle_undefined_opcode_exception(),
                }
            }

            VmxBasicExitReason::ControlRegisterAccesses => {
                diag::EXIT_CR_ACCESS.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(5, Relaxed);
                diag::LAST_HANDLER_DETAIL.store(exit_qualification, Relaxed);
                handle_cr_access(guest_registers)
            }

            reason if vmx_probe_instruction_should_inject_ud(reason) => {
                diag::EXIT_VMX_INSTR.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(6, Relaxed);
                diag::LAST_HANDLER_DETAIL.store(exit_reason as u64, Relaxed);
                handle_vmx_instruction(reason, guest_registers)
            }

            VmxBasicExitReason::MonitorTrapFlag => {
                diag::LAST_HANDLER_ID.store(7, Relaxed);
                handle_mtf(vmx)
            }

            VmxBasicExitReason::Mwait => {
                diag::LAST_HANDLER_ID.store(60, Relaxed);
                idle::handle_mwait(guest_registers, vmx)
            }

            VmxBasicExitReason::Monitor => {
                diag::LAST_HANDLER_ID.store(61, Relaxed);
                idle::handle_monitor(guest_registers, vmx)
            }

            VmxBasicExitReason::Rdmsr => {
                diag::EXIT_MSR.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(8, Relaxed);
                diag::LAST_HANDLER_DETAIL.store(guest_registers.rcx, Relaxed);
                handle_msr_access(guest_registers, MsrAccessType::Read)
            }
            VmxBasicExitReason::Wrmsr => {
                diag::EXIT_MSR.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(9, Relaxed);
                diag::LAST_HANDLER_DETAIL.store(guest_registers.rcx, Relaxed);
                handle_msr_access(guest_registers, MsrAccessType::Write)
            }
            VmxBasicExitReason::Invd => {
                diag::LAST_HANDLER_ID.store(10, Relaxed);
                handle_invd(guest_registers)
            }
            VmxBasicExitReason::WbinvdOrWbnoinvd => {
                diag::LAST_HANDLER_ID.store(11, Relaxed);
                handle_wbinvd_or_wbnoinvd()
            }
            VmxBasicExitReason::Rdtsc => {
                diag::EXIT_RDTSC.fetch_add(1, Relaxed);
                handle_rdtsc(guest_registers, vmx)
            }
            VmxBasicExitReason::Rdtscp => {
                diag::EXIT_RDTSC.fetch_add(1, Relaxed);
                handle_rdtscp(guest_registers, vmx)
            }
            VmxBasicExitReason::EptViolation => {
                diag::EXIT_EPT_VIOLATION.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(14, Relaxed);
                handle_ept_violation(guest_registers, vmx)
            }
            VmxBasicExitReason::EptMisconfiguration => {
                diag::EXIT_EPT_MISCONFIG.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(15, Relaxed);
                handle_ept_misconfiguration()
            }
            VmxBasicExitReason::Invept => {
                diag::LAST_HANDLER_ID.store(16, Relaxed);
                handle_invept()
            }
            VmxBasicExitReason::Invvpid => {
                diag::LAST_HANDLER_ID.store(17, Relaxed);
                handle_invvpid()
            }
            VmxBasicExitReason::Xsetbv => {
                diag::EXIT_XSETBV.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(18, Relaxed);
                handle_xsetbv(guest_registers)
            }
            VmxBasicExitReason::VmxPreemptionTimerExpired => {
                diag::EXIT_PREEMPT.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(19, Relaxed);
                let _ = vmwrite_checked(
                    x86::vmx::vmcs::guest::VMX_PREEMPTION_TIMER_VALUE,
                    0x0060_0000u64,
                );
                let inject_nmi = diag::cpu_record_timer_rip(guest_registers.rip);
                if inject_nmi {
                    // Inject NMI into guest to force BSOD + crash dump
                    // VM-entry interruption info: valid=1, type=NMI(2), vector=2
                    let nmi_info: u64 = (1u64 << 31) | (2u64 << 8) | 2u64;
                    let _ = vmwrite_checked(
                        x86::vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
                        nmi_info,
                    );
                }
                ExitType::Continue
            }
            _ => {
                diag::EXIT_OTHER.fetch_add(1, Relaxed);
                diag::LAST_HANDLER_ID.store(99, Relaxed);
                diag::LAST_HANDLER_DETAIL.store(exit_reason as u64, Relaxed);
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

        reinject_idt_vectoring_event();
        diag::cpu_enter_phase(diag::PHASE_CHECK_NMI);
        super::host_idt::check_pending_nmi();
        diag::cpu_enter_phase(diag::PHASE_PRE_VMRESUME);
        diag::watchdog_handler_finish(guest_registers.rip);
        if lbr_saved {
            crate::intel::lbr::restore_lbr();
        }

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

        // Preserve the guest MXCSR across VMXOFF. Host handler code may have
        // executed SSE instructions and mutated MXCSR (rounding mode, flush-to-
        // zero, denormals-are-zero flags). Without saving it now and restoring
        // it after `restore_after_vmxoff`, guest-side FPU/SSE state resumes
        // with our HV's control bits, which can silently corrupt subsequent
        // floating point results in the returning thread.
        let saved_mxcsr = {
            let mut buf: u32 = 0;
            unsafe {
                core::arch::asm!(
                    "stmxcsr [{}]",
                    in(reg) &mut buf,
                    options(nostack, preserves_flags),
                );
            }
            buf
        };

        support::vmxoff()?;
        unsafe {
            guest_state.restore_after_vmxoff(vmx);
            core::arch::asm!(
                "ldmxcsr [{}]",
                in(reg) &saved_mxcsr,
                options(nostack, preserves_flags),
            );
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

/// Emulates correct hardware behavior for VMX instructions executed in the guest.
///
/// Uses CR4_READ_SHADOW (the guest's view of CR4) to decide behavior:
/// - Guest sees VMXE=0 → #UD (matches bare metal without VMX enabled)
/// - Guest sees VMXE=1, CPL>0 → #GP(0)
/// - Guest sees VMXE=1, CPL=0 → VMfailInvalid (CF=1)
fn handle_vmx_instruction(
    reason: VmxBasicExitReason,
    guest_registers: &mut GuestRegisters,
) -> ExitType {
    use crate::intel::events::EventInjection;

    // GETSEC/ENCLS/ENCLV: always #UD (not VMX instructions proper)
    if matches!(
        reason,
        VmxBasicExitReason::Getsec | VmxBasicExitReason::Encls | VmxBasicExitReason::Enclv
    ) {
        EventInjection::vmentry_inject_ud();
        return ExitType::Continue;
    }

    // Use the READ SHADOW — what the guest believes CR4 contains.
    let cr4_shadow =
        vmread_checked(x86::vmx::vmcs::control::CR4_READ_SHADOW).unwrap_or(0);
    if cr4_shadow & (1 << 13) == 0 {
        // Guest's view: CR4.VMXE=0 → #UD per SDM
        EventInjection::vmentry_inject_ud();
        return ExitType::Continue;
    }

    // CR4.VMXE=1 in guest's view: check CPL via CS selector RPL
    let cs_sel = vmread_checked(guest::CS_SELECTOR).unwrap_or(0);
    if cs_sel & 3 != 0 {
        // CPL > 0 → #GP(0) per SDM
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // CPL=0, CR4.VMXE=1: emulate VMfailInvalid
    // Set CF=1, clear ZF/PF/AF/SF/OF, advance RIP
    const CF: u64 = 1 << 0;
    const PF: u64 = 1 << 2;
    const AF: u64 = 1 << 4;
    const ZF: u64 = 1 << 6;
    const SF: u64 = 1 << 7;
    const OF: u64 = 1 << 11;
    let rflags = (guest_registers.rflags & !(CF | PF | AF | ZF | SF | OF)) | CF;
    guest_registers.rflags = rflags;
    let _ = vmwrite_checked(guest::RFLAGS, rflags);

    ExitType::IncrementRIP
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
