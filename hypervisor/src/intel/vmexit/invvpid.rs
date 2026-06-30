//! Manages guest INVVPID VM exits.

use crate::intel::{events::EventInjection, vmexit::ExitType};

/// Handles the INVVPID VM exit.
///
/// Injects #UD for guest INVVPID. With VMX hidden from CPUID, guest-visible VMX
/// instructions must not appear to execute successfully.
///
/// # Returns
///
/// * `ExitType::Continue` - Re-enter the guest with a pending #UD.
pub fn handle_invvpid() -> ExitType {
    log::debug!("Handling INVVPID VM exit...");
    handle_invvpid_with(EventInjection::vmentry_inject_ud)
}

fn handle_invvpid_with<F>(inject_ud: F) -> ExitType
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
    fn guest_invvpid_injects_ud_without_advancing_rip() {
        let mut injected = false;

        assert!(matches!(
            handle_invvpid_with(|| injected = true),
            ExitType::Continue
        ));
        assert!(injected);
    }
}
