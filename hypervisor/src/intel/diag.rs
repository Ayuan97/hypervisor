use {
    crate::error::HypervisorError,
    core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
};

pub static EXIT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static EXIT_CPUID: AtomicU64 = AtomicU64::new(0);
pub static EXIT_EXT_INT: AtomicU64 = AtomicU64::new(0);
pub static EXIT_EXCEPTION: AtomicU64 = AtomicU64::new(0);
pub static EXIT_EPT_VIOLATION: AtomicU64 = AtomicU64::new(0);
pub static EXIT_EPT_MISCONFIG: AtomicU64 = AtomicU64::new(0);
pub static EXIT_CR_ACCESS: AtomicU64 = AtomicU64::new(0);
pub static EXIT_XSETBV: AtomicU64 = AtomicU64::new(0);
pub static EXIT_MSR: AtomicU64 = AtomicU64::new(0);
pub static EXIT_OTHER: AtomicU64 = AtomicU64::new(0);
pub static LAST_EXIT_REASON: AtomicU64 = AtomicU64::new(u64::MAX);

pub static CTL_PINBASED: AtomicU64 = AtomicU64::new(0);
pub static CTL_PRIMARY: AtomicU64 = AtomicU64::new(0);
pub static CTL_SECONDARY: AtomicU64 = AtomicU64::new(0);
pub static CTL_EXIT: AtomicU64 = AtomicU64::new(0);
pub static CTL_ENTRY: AtomicU64 = AtomicU64::new(0);
pub static TSC_OFFSET: AtomicU64 = AtomicU64::new(0);
pub static BOOT_STAGE: AtomicU64 = AtomicU64::new(0);
pub static DIAGNOSTICS_SEALED: AtomicBool = AtomicBool::new(false);
const BOOT_STOP_STAGE: u64 = parse_boot_stop_stage(option_env!("HV_BOOT_STOP_STAGE"));

pub const fn parse_boot_stop_stage(value: Option<&str>) -> u64 {
    let Some(value) = value else {
        return 0;
    };

    let bytes = value.as_bytes();
    let mut i = 0;
    let mut parsed = 0u64;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte < b'0' || byte > b'9' {
            return 0;
        }
        parsed = parsed * 10 + (byte - b'0') as u64;
        i += 1;
    }
    parsed
}

pub fn set_boot_stage(stage: u64) {
    BOOT_STAGE.store(stage, Relaxed);
}

pub fn boot_stage(stage: u64) -> Result<(), HypervisorError> {
    set_boot_stage(stage);
    log::info!("hv stage {}", stage);
    if stop_requested_at(stage) {
        log::info!("hv stop stage {}", stage);
        Err(HypervisorError::BootStageStop)
    } else {
        Ok(())
    }
}

pub fn stop_requested_at(stage: u64) -> bool {
    BOOT_STOP_STAGE != 0 && stage >= BOOT_STOP_STAGE
}

pub fn seal_diagnostics() {
    DIAGNOSTICS_SEALED.store(true, Relaxed);
}

pub fn diagnostics_sealed() -> bool {
    DIAGNOSTICS_SEALED.load(Relaxed)
}

pub fn counter(id: u64) -> u64 {
    match id {
        0 => EXIT_TOTAL.load(Relaxed),
        1 => EXIT_CPUID.load(Relaxed),
        2 => EXIT_EXT_INT.load(Relaxed),
        3 => EXIT_EXCEPTION.load(Relaxed),
        4 => EXIT_EPT_VIOLATION.load(Relaxed),
        5 => EXIT_EPT_MISCONFIG.load(Relaxed),
        6 => EXIT_CR_ACCESS.load(Relaxed),
        7 => EXIT_XSETBV.load(Relaxed),
        8 => EXIT_OTHER.load(Relaxed),
        9 => EXIT_MSR.load(Relaxed),
        10 => super::host_idt::HOST_GP_COUNT.load(Relaxed),
        11 => super::host_idt::HOST_NMI_COUNT.load(Relaxed),
        _ => u64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_stop_stage_parser_accepts_decimal_only() {
        assert_eq!(parse_boot_stop_stage(None), 0);
        assert_eq!(parse_boot_stop_stage(Some("")), 0);
        assert_eq!(parse_boot_stop_stage(Some("700")), 700);
        assert_eq!(parse_boot_stop_stage(Some("70x")), 0);
    }
}

pub fn control(id: u64) -> u64 {
    match id {
        0 => CTL_PINBASED.load(Relaxed),
        1 => CTL_PRIMARY.load(Relaxed),
        2 => CTL_SECONDARY.load(Relaxed),
        3 => CTL_EXIT.load(Relaxed),
        4 => CTL_ENTRY.load(Relaxed),
        5 => unsafe { crate::utils::nt::IDENTITY_CR3 },
        6 => LAST_EXIT_REASON.load(Relaxed),
        7 => super::host_idt::GP_FAULT_RIP.load(Relaxed),
        8 => TSC_OFFSET.load(Relaxed),
        9 => BOOT_STAGE.load(Relaxed),
        _ => u64::MAX,
    }
}
