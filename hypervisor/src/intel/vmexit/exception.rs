//! Module handling VM exits due to exceptions or non-maskable interrupts (NMIs).
//! It includes handling for various types of exceptions such as page faults,
//! general protection faults, breakpoints, and invalid opcodes.

use {
    crate::{
        intel::{
            ept::hooks::HookType,
            events::EventInjection,
            support::{vmread_checked, vmwrite_checked},
            vmerror::{ExceptionInterrupt, InterruptionType, VmExitInterruptionInformation},
            vmexit::ExitType,
            vmx::Vmx,
        },
        utils::capture::GuestRegisters,
    },
    x86::vmx::vmcs,
};

/// Handles exceptions and NMIs that occur during VM execution.
///
/// This function is called when the VM exits due to an exception or NMI.
/// It determines the type of exception, handles it accordingly, and prepares
/// the VM for resumption.
///
/// # Arguments
///
/// * `guest_registers` - A mutable reference to the guest's register state.
/// * `vmx` - A mutable reference to the Vmx structure representing the current VM.
///
/// # Returns
///
/// * `ExitType::Continue` - Indicating that VM execution should continue after handling the exception
#[rustfmt::skip]
pub fn handle_exception(guest_registers: &mut GuestRegisters, vmx: &mut Vmx) -> ExitType {
    log::debug!("Handling ExceptionOrNmi VM exit...");

    let interruption_info_value = match vmread_checked(vmcs::ro::VMEXIT_INTERRUPTION_INFO) {
        Ok(value) => value as u32,
        Err(error) => {
            log::error!("Failed to read VM-exit interruption info: {:?}", error);
            EventInjection::vmentry_inject_ud();
            return ExitType::Continue;
        }
    };

    let interruption_error_code_value = match vmread_checked(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE) {
        Ok(value) => value as u32,
        Err(error) => {
            log::error!("Failed to read VM-exit interruption error code: {:?}", error);
            EventInjection::vmentry_inject_ud();
            return ExitType::Continue;
        }
    };

    let Some(interruption_info) = VmExitInterruptionInformation::from_u32(interruption_info_value) else {
        EventInjection::vmentry_reinject(interruption_info_value, interruption_error_code_value);
        return ExitType::Continue;
    };

    match interruption_info.interruption_type {
        InterruptionType::NonMaskableInterrupt => {
            EventInjection::vmentry_inject_nmi();
        },
        InterruptionType::HardwareException => {
            if let Some(exception_interrupt) = ExceptionInterrupt::from_u32(interruption_info.vector.into()) {
                match exception_interrupt {
                    ExceptionInterrupt::PageFault => {
                        EventInjection::vmentry_inject_pf(interruption_error_code_value);
                    },
                    ExceptionInterrupt::GeneralProtectionFault => {
                        EventInjection::vmentry_inject_gp(interruption_error_code_value);
                    },
                    ExceptionInterrupt::Breakpoint => {
                        handle_breakpoint_exception(guest_registers, vmx);
                    },
                    ExceptionInterrupt::InvalidOpcode => {
                        EventInjection::vmentry_inject_ud();
                    },
                    _ => {
                        EventInjection::vmentry_reinject(interruption_info_value, interruption_error_code_value);
                    }
                }
            } else {
                EventInjection::vmentry_reinject(interruption_info_value, interruption_error_code_value);
            }
        },
        _ => {
            EventInjection::vmentry_reinject(interruption_info_value, interruption_error_code_value);
        }
    }

    ExitType::Continue
}

/// Handles breakpoint (`#BP`) exceptions specifically.
///
/// When a breakpoint exception occurs, this function checks for a registered hook
/// at the current instruction pointer (RIP). If a hook is found, it transfers control
/// to the hook's handler. Otherwise, it injects a breakpoint exception into the VM.
///
/// # Arguments
///
/// * `guest_registers` - A mutable reference to the guest's current register state.
/// * `vmx` - A mutable reference to the Vmx structure.
fn handle_breakpoint_exception(guest_registers: &mut GuestRegisters, vmx: &mut Vmx) {
    log::debug!("Breakpoint Exception");

    let hook_manager = unsafe { vmx.shared_data.as_mut().hook_manager.as_mut() };

    log::trace!("Finding hook for RIP: {:#x}", guest_registers.rip);

    // Find the handler address for the current instruction pointer (RIP) and
    // transfer the execution to it. If we couldn't find a hook, we inject the
    // #BP exception.
    //
    if let Some(Some(handler)) =
        hook_manager
            .find_hook_by_address(guest_registers.rip)
            .map(|hook| {
                log::trace!("Found hook for RIP: {:#x}", guest_registers.rip);
                if let HookType::Function { inline_hook } = &hook.hook_type {
                    log::trace!("Getting handler address");
                    Some(inline_hook.handler_address())
                } else {
                    None
                }
            })
    {
        // Call our hook handle function (it will automatically call trampoline).
        log::trace!("Transferring execution to handler: {:#x}", handler);
        guest_registers.rip = handler;
        if let Err(error) = vmwrite_checked(vmcs::guest::RIP, guest_registers.rip) {
            log::error!("Failed to redirect guest RIP for breakpoint hook: {:?}", error);
            EventInjection::vmentry_inject_bp();
            return;
        }

        log::debug!("Breakpoint (int3) hook handled successfully!");
    } else {
        EventInjection::vmentry_inject_bp();
        log::debug!("Breakpoint exception handled successfully!");
    };
}

/// Handles undefined opcode (`#UD`) exceptions.
///
/// This function is invoked when the VM attempts to execute an invalid or undefined
/// opcode. It injects an undefined opcode exception into the VM.
///
/// # Returns
///
/// * `ExitType::Continue` - Indicating that VM execution should continue.
pub fn handle_undefined_opcode_exception() -> ExitType {
    log::debug!("Undefined Opcode Exception");

    EventInjection::vmentry_inject_ud();

    log::debug!("Undefined Opcode Exception handled successfully!");

    ExitType::Continue
}
