use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

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
        _ => u64::MAX,
    }
}
