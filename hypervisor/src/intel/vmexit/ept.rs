use {
    crate::{
        intel::{
            bugcheck_hook,
            events::EventInjection,
            invept::invept_all_contexts,
            support::{vmread_checked, vmwrite_checked},
            vmerror::EptViolationExitQualification,
            vmexit::ExitType,
            vmx::Vmx,
        },
        utils::capture::GuestRegisters,
    },
    x86::vmx::vmcs::{self, guest as vmcs_guest},
};

fn monitor_trap_flag_bit() -> u64 {
    vmcs::control::PrimaryControls::MONITOR_TRAP_FLAG.bits() as u64
}

fn enable_monitor_trap_flag(proc_ctl: u64) -> u64 {
    proc_ctl | monitor_trap_flag_bit()
}

fn disable_monitor_trap_flag(proc_ctl: u64) -> u64 {
    proc_ctl & !monitor_trap_flag_bit()
}

#[cfg(any(feature = "secondary-ept", test))]
fn is_execute_violation_on_read_write_page(eq: &EptViolationExitQualification) -> bool {
    eq.instruction_fetch && eq.readable && eq.writable && !eq.executable
}

#[cfg(any(feature = "secondary-ept", test))]
fn is_memory_violation_on_execute_only_page(eq: &EptViolationExitQualification) -> bool {
    (eq.data_read || eq.data_write) && !eq.readable && !eq.writable && eq.executable
}

#[rustfmt::skip]
pub fn handle_ept_violation(_guest_registers: &mut GuestRegisters, _vmx: &mut Vmx) -> ExitType {
    let guest_physical_address = match vmread_checked(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL) {
        Ok(value) => value,
        Err(error) => {
            log::error!("Failed to read EPT violation guest physical address: {:?}", error);
            EventInjection::vmentry_inject_gp(0);
            return ExitType::Continue;
        }
    };

    let exit_qualification_value = match vmread_checked(vmcs::ro::EXIT_QUALIFICATION) {
        Ok(value) => value,
        Err(error) => {
            log::error!("Failed to read EPT violation qualification: {:?}", error);
            EventInjection::vmentry_inject_gp(0);
            return ExitType::Continue;
        }
    };
    let eq = EptViolationExitQualification::from_exit_qualification(exit_qualification_value);

    if !eq.readable && !eq.writable && !eq.executable {
        log::error!("EPT violation: unmapped PA {:#x} (no RWX)", guest_physical_address);
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // KeBugCheckEx entry-hook: cloak page (RW only) triggers instruction-
    // fetch violations. If guest RIP is inside the watched function, latch
    // the hit and permanently uncloak; otherwise MTF single-step past the
    // neighbouring instruction and re-cloak in the MTF handler.
    if eq.instruction_fetch && bugcheck_hook::matches(guest_physical_address) {
        let guest_rip = vmread_checked(vmcs_guest::RIP).unwrap_or(0);
        let ept = &mut *_vmx.shared_data_mut().primary_ept;
        match bugcheck_hook::check_ept_violation(guest_physical_address, guest_rip, ept) {
            bugcheck_hook::HookOutcome::Latched => {
                return ExitType::Continue;
            }
            bugcheck_hook::HookOutcome::NeedsStep => {
                let proc_ctl = match vmread_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS) {
                    Ok(v) => v,
                    Err(_) => {
                        // Arm state is inconsistent; leave the page executable and
                        // give up on re-cloaking rather than corrupt guest state.
                        return ExitType::Continue;
                    }
                };
                if vmwrite_checked(
                    vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                    enable_monitor_trap_flag(proc_ctl),
                )
                .is_err()
                {
                    return ExitType::Continue;
                }
                _vmx.bugcheck_hook_mtf_recloak = true;
                return ExitType::Continue;
            }
            bugcheck_hook::HookOutcome::NotOurs => {
                // Fall through — shouldn't happen given the matches() gate
                // above, but be safe.
            }
        }
    }

    #[cfg(feature = "secondary-ept")]
    {
        if is_execute_violation_on_read_write_page(&eq) {
            let secondary_eptp = _vmx.shared_data_ref().secondary_eptp;
            if let Err(error) = vmwrite_checked(vmcs::control::EPTP_FULL, secondary_eptp) {
                log::error!("Failed to switch to secondary EPTP: {:?}", error);
                EventInjection::vmentry_inject_gp(0);
                return ExitType::Continue;
            }
            let proc_ctl = match vmread_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS) {
                Ok(value) => value,
                Err(error) => {
                    log::error!("Failed to read primary processor controls: {:?}", error);
                    EventInjection::vmentry_inject_gp(0);
                    return ExitType::Continue;
                }
            };
            if let Err(error) = vmwrite_checked(
                vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                enable_monitor_trap_flag(proc_ctl),
            ) {
                log::error!("Failed to enable monitor trap flag: {:?}", error);
                let primary_eptp = _vmx.shared_data_ref().primary_eptp;
                let _ = vmwrite_checked(vmcs::control::EPTP_FULL, primary_eptp);
                invept_all_contexts();
                EventInjection::vmentry_inject_gp(0);
                return ExitType::Continue;
            }
            _vmx.mtf_recloak_pa = Some(guest_physical_address);
            invept_all_contexts();
            return ExitType::Continue;
        }

        if is_memory_violation_on_execute_only_page(&eq) {
            let primary_eptp = _vmx.shared_data_ref().primary_eptp;
            if let Err(error) = vmwrite_checked(vmcs::control::EPTP_FULL, primary_eptp) {
                log::error!("Failed to switch to primary EPTP: {:?}", error);
                EventInjection::vmentry_inject_gp(0);
                return ExitType::Continue;
            }
            let proc_ctl = match vmread_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS) {
                Ok(value) => value,
                Err(error) => {
                    log::error!("Failed to read primary processor controls: {:?}", error);
                    EventInjection::vmentry_inject_gp(0);
                    return ExitType::Continue;
                }
            };
            if let Err(error) = vmwrite_checked(
                vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                disable_monitor_trap_flag(proc_ctl),
            ) {
                log::error!("Failed to disable monitor trap flag: {:?}", error);
                EventInjection::vmentry_inject_gp(0);
                return ExitType::Continue;
            }
            _vmx.mtf_recloak_pa.take();
            invept_all_contexts();
            return ExitType::Continue;
        }
    }

    // Unhandled EPT violation: inject #GP to prevent infinite re-execution loop.
    EventInjection::vmentry_inject_gp(0);
    ExitType::Continue
}

pub fn handle_mtf(vmx: &mut Vmx) -> ExitType {
    if vmx.mtf_recloak_pa.take().is_some() {
        #[cfg(feature = "secondary-ept")]
        {
            let primary_eptp = vmx.shared_data_ref().primary_eptp;
            if let Err(error) = vmwrite_checked(vmcs::control::EPTP_FULL, primary_eptp) {
                log::error!("Failed to restore primary EPTP on MTF: {:?}", error);
                EventInjection::vmentry_inject_gp(0);
                return ExitType::Continue;
            }
            invept_all_contexts();
        }
    }

    if vmx.bugcheck_hook_mtf_recloak {
        vmx.bugcheck_hook_mtf_recloak = false;
        let ept = &mut *vmx.shared_data_mut().primary_ept;
        bugcheck_hook::recloak_after_step(ept);
        invept_all_contexts();
    }

    let proc_ctl = match vmread_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS) {
        Ok(value) => value,
        Err(error) => {
            log::error!(
                "Failed to read primary processor controls on MTF: {:?}",
                error
            );
            EventInjection::vmentry_inject_gp(0);
            return ExitType::Continue;
        }
    };
    let cleared = disable_monitor_trap_flag(proc_ctl);
    if proc_ctl != cleared {
        if let Err(error) = vmwrite_checked(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, cleared)
        {
            log::error!("Failed to disable monitor trap flag on MTF: {:?}", error);
            EventInjection::vmentry_inject_gp(0);
        }
    }

    ExitType::Continue
}

pub fn handle_ept_misconfiguration() -> ExitType {
    let guest_physical_address = match vmread_checked(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL) {
        Ok(value) => value,
        Err(error) => {
            log::error!(
                "Failed to read EPT misconfiguration guest physical address: {:?}",
                error
            );
            0
        }
    };
    log::error!("EPT Misconfiguration at PA {:#x}", guest_physical_address);
    EventInjection::vmentry_inject_gp(0);
    ExitType::Continue
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_violation_on_rw_page_enters_hook_view() {
        let eq =
            EptViolationExitQualification::from_exit_qualification((1 << 2) | (1 << 3) | (1 << 4));

        assert!(is_execute_violation_on_read_write_page(&eq));
    }

    #[test]
    fn memory_violation_on_execute_only_page_leaves_hook_view() {
        let eq = EptViolationExitQualification::from_exit_qualification((1 << 0) | (1 << 5));

        assert!(is_memory_violation_on_execute_only_page(&eq));
    }

    #[test]
    fn monitor_trap_flag_helpers_toggle_only_mtf_bit() {
        let mtf = vmcs::control::PrimaryControls::MONITOR_TRAP_FLAG.bits() as u64;
        let base = 0x55aa_u64 & !mtf;

        assert_eq!(enable_monitor_trap_flag(base), base | mtf);
        assert_eq!(disable_monitor_trap_flag(base | mtf), base);
    }
}
