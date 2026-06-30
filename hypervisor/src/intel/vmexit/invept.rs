//! Handles guest INVEPT VM exits.

use crate::intel::{events::EventInjection, vmexit::ExitType};

/// Handles the INVEPT VM exit.
///
/// Injects #UD for guest INVEPT. With VMX hidden from CPUID, guest-visible VMX
/// instructions must not appear to execute successfully.
///
/// # Returns
/// * `ExitType::Continue` - Re-enter the guest with a pending #UD.
pub fn handle_invept() -> ExitType {
    log::debug!("Handling INVEPT VM exit...");
    handle_invept_with(EventInjection::vmentry_inject_ud)
}

fn handle_invept_with<F>(inject_ud: F) -> ExitType
where
    F: FnOnce(),
{
    inject_ud();
    ExitType::Continue
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_invept_injects_ud_without_advancing_rip() {
        let mut injected = false;

        assert!(matches!(
            handle_invept_with(|| injected = true),
            ExitType::Continue
        ));
        assert!(injected);
    }
}
