//! Manages INVD VM exits to handle guest VM cache invalidation requests securely.

use {
    crate::{
        intel::{events::EventInjection, support::vmread_checked, vmexit::ExitType},
        utils::capture::GuestRegisters,
        utils::instructions::wbinvd,
    },
    x86::vmx::vmcs,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CacheInstructionAction {
    Execute,
    GeneralProtection,
}

/// Manages the INVD instruction VM exit by logging the event, performing a controlled
/// cache invalidation, and advancing the guest's instruction pointer.
///
/// # Arguments
///
/// * `registers` - General-purpose registers of the guest VM at the VM exit.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `INVD` instruction in the VM.
pub fn handle_invd(_guest_registers: &mut GuestRegisters) -> ExitType {
    log::debug!("Handling INVD VM exit...");

    if classify_cache_instruction(guest_cpl().unwrap_or(3))
        == CacheInstructionAction::GeneralProtection
    {
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // Perform WBINVD to write back and invalidate the hypervisor's caches.
    // This ensures that any modified data is written to memory before cache lines are invalidated.
    wbinvd();
    // Advances the guest's instruction pointer to the next instruction to be executed.

    log::debug!("INVD VMEXIT handled successfully!");

    ExitType::IncrementRIP
}

pub fn handle_wbinvd_or_wbnoinvd() -> ExitType {
    log::debug!("Handling WBINVD/WBNOINVD VM exit...");
    handle_wbinvd_or_wbnoinvd_with(guest_cpl().unwrap_or(3), || wbinvd())
}

fn handle_wbinvd_or_wbnoinvd_with<F>(guest_cpl: u16, writeback: F) -> ExitType
where
    F: FnOnce(),
{
    match classify_cache_instruction(guest_cpl) {
        CacheInstructionAction::Execute => {
            writeback();
            ExitType::IncrementRIP
        }
        CacheInstructionAction::GeneralProtection => {
            EventInjection::vmentry_inject_gp(0);
            ExitType::Continue
        }
    }
}

fn guest_cpl() -> Option<u16> {
    vmread_checked(vmcs::guest::CS_SELECTOR)
        .ok()
        .map(|selector| (selector & 0x3) as u16)
}

fn classify_cache_instruction(guest_cpl: u16) -> CacheInstructionAction {
    if guest_cpl == 0 {
        CacheInstructionAction::Execute
    } else {
        CacheInstructionAction::GeneralProtection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_writeback_exit_advances_guest_rip() {
        assert!(matches!(
            handle_wbinvd_or_wbnoinvd_with(0, || ()),
            ExitType::IncrementRIP
        ));
    }

    #[test]
    fn user_mode_cache_instruction_injects_general_protection() {
        assert_eq!(
            classify_cache_instruction(3),
            CacheInstructionAction::GeneralProtection
        );
    }
}
