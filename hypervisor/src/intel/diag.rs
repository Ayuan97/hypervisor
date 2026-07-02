use {
    crate::error::HypervisorError,
    core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
};

const ZERO_U64: AtomicU64 = AtomicU64::new(0);

pub const MAX_BREADCRUMB_CPUS: usize = 256;
pub const BREADCRUMB_FIELD_COUNT: u64 = 0;
pub const BREADCRUMB_FIELD_EXIT_REASON: u64 = 1;
pub const BREADCRUMB_FIELD_BASIC_REASON: u64 = 2;
pub const BREADCRUMB_FIELD_GUEST_RIP: u64 = 3;
pub const BREADCRUMB_FIELD_GUEST_RSP: u64 = 4;
pub const BREADCRUMB_FIELD_GUEST_CR3: u64 = 5;
pub const BREADCRUMB_FIELD_GUEST_RFLAGS: u64 = 6;
pub const BREADCRUMB_FIELD_EXIT_QUAL: u64 = 7;
pub const BREADCRUMB_FIELD_GUEST_RAX: u64 = 8;
pub const BREADCRUMB_FIELD_GUEST_RCX: u64 = 9;
pub const BREADCRUMB_FIELD_GUEST_RDX: u64 = 10;
pub const BREADCRUMB_FIELD_DETAIL: u64 = 11;
pub const BREADCRUMB_FIELD_LIMIT: usize = 12;

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
pub static CLIENT_READS_ARMED: AtomicBool = AtomicBool::new(false);
const BOOT_STOP_STAGE: u64 = parse_boot_stop_stage(option_env!("HV_BOOT_STOP_STAGE"));

static BREADCRUMB_COUNT: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_EXIT_REASON: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_BASIC_REASON: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RIP: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RSP: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_CR3: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RFLAGS: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_EXIT_QUAL: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RAX: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RCX: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_GUEST_RDX: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];
static BREADCRUMB_DETAIL: [AtomicU64; MAX_BREADCRUMB_CPUS] = [ZERO_U64; MAX_BREADCRUMB_CPUS];

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

pub fn arm_client_reads() {
    crate::intel::client_read::reclaim_completed_result_for_new_client();
    CLIENT_READS_ARMED.store(true, Relaxed);
}

pub fn client_reads_armed() -> bool {
    CLIENT_READS_ARMED.load(Relaxed)
}

pub fn record_current_vmexit(
    exit_reason: u64,
    guest_rip: u64,
    guest_rsp: u64,
    guest_cr3: u64,
    guest_rflags: u64,
    exit_qualification: u64,
    guest_rax: u64,
    guest_rcx: u64,
    guest_rdx: u64,
    detail: u64,
) {
    record_vmexit_for_cpu(
        rdtscp_aux() as usize & 0xFF,
        exit_reason,
        guest_rip,
        guest_rsp,
        guest_cr3,
        guest_rflags,
        exit_qualification,
        guest_rax,
        guest_rcx,
        guest_rdx,
        detail,
    );
}

pub fn record_vmexit_for_cpu(
    cpu: usize,
    exit_reason: u64,
    guest_rip: u64,
    guest_rsp: u64,
    guest_cr3: u64,
    guest_rflags: u64,
    exit_qualification: u64,
    guest_rax: u64,
    guest_rcx: u64,
    guest_rdx: u64,
    detail: u64,
) {
    if cpu >= MAX_BREADCRUMB_CPUS {
        return;
    }

    BREADCRUMB_EXIT_REASON[cpu].store(exit_reason, Relaxed);
    BREADCRUMB_BASIC_REASON[cpu].store(exit_reason & 0xFFFF, Relaxed);
    BREADCRUMB_GUEST_RIP[cpu].store(guest_rip, Relaxed);
    BREADCRUMB_GUEST_RSP[cpu].store(guest_rsp, Relaxed);
    BREADCRUMB_GUEST_CR3[cpu].store(guest_cr3, Relaxed);
    BREADCRUMB_GUEST_RFLAGS[cpu].store(guest_rflags, Relaxed);
    BREADCRUMB_EXIT_QUAL[cpu].store(exit_qualification, Relaxed);
    BREADCRUMB_GUEST_RAX[cpu].store(guest_rax, Relaxed);
    BREADCRUMB_GUEST_RCX[cpu].store(guest_rcx, Relaxed);
    BREADCRUMB_GUEST_RDX[cpu].store(guest_rdx, Relaxed);
    BREADCRUMB_DETAIL[cpu].store(detail, Relaxed);
    BREADCRUMB_COUNT[cpu].fetch_add(1, Relaxed);
}

pub fn breadcrumb(cpu: u64, field: u64) -> u64 {
    let cpu = cpu as usize;
    if cpu >= MAX_BREADCRUMB_CPUS {
        return u64::MAX;
    }

    match field {
        BREADCRUMB_FIELD_COUNT => BREADCRUMB_COUNT[cpu].load(Relaxed),
        BREADCRUMB_FIELD_EXIT_REASON => BREADCRUMB_EXIT_REASON[cpu].load(Relaxed),
        BREADCRUMB_FIELD_BASIC_REASON => BREADCRUMB_BASIC_REASON[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RIP => BREADCRUMB_GUEST_RIP[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RSP => BREADCRUMB_GUEST_RSP[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_CR3 => BREADCRUMB_GUEST_CR3[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RFLAGS => BREADCRUMB_GUEST_RFLAGS[cpu].load(Relaxed),
        BREADCRUMB_FIELD_EXIT_QUAL => BREADCRUMB_EXIT_QUAL[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RAX => BREADCRUMB_GUEST_RAX[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RCX => BREADCRUMB_GUEST_RCX[cpu].load(Relaxed),
        BREADCRUMB_FIELD_GUEST_RDX => BREADCRUMB_GUEST_RDX[cpu].load(Relaxed),
        BREADCRUMB_FIELD_DETAIL => BREADCRUMB_DETAIL[cpu].load(Relaxed),
        _ => u64::MAX,
    }
}

fn rdtscp_aux() -> u32 {
    let aux: u32;
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("ecx") aux,
            out("eax") _,
            out("edx") _,
            options(nomem, nostack),
        );
    }
    aux
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

    #[test]
    fn client_read_request_waits_for_worker_completion() {
        let _guard = crate::intel::client_read::test_lock();
        crate::intel::client_read::reset_for_test();

        let seq = crate::intel::client_read::submit_physical_read(0x1000, 8);
        assert_ne!(seq, 0);
        assert_eq!(
            crate::intel::client_read::poll_physical_read(seq),
            crate::intel::client_read::READ_PENDING
        );

        crate::intel::client_read::complete_for_test(seq, 0x1122_3344_5566_7788, true);
        assert_eq!(
            crate::intel::client_read::poll_physical_read(seq),
            0x1122_3344_5566_7788
        );
    }

    #[test]
    fn breadcrumb_records_last_vmexit_for_cpu_slot() {
        reset_breadcrumbs_for_test();

        record_vmexit_for_cpu(
            3,
            0x8000_000a,
            0x1111_2222_3333_4444,
            0x2222_3333_4444_5555,
            0x3333_4444_5555_6666,
            0x202,
            0x7777,
            0xaaaaaaaa_bbbbbbbb,
            0xcccccccc_dddddddd,
            0xeeeeeeee_ffffffff,
            0x1234,
        );

        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_COUNT), 1);
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_EXIT_REASON), 0x8000_000a);
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_BASIC_REASON), 10);
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RIP),
            0x1111_2222_3333_4444
        );
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RSP),
            0x2222_3333_4444_5555
        );
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_CR3),
            0x3333_4444_5555_6666
        );
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_GUEST_RFLAGS), 0x202);
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_EXIT_QUAL), 0x7777);
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RAX),
            0xaaaaaaaa_bbbbbbbb
        );
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RCX),
            0xcccccccc_dddddddd
        );
        assert_eq!(
            breadcrumb(3, BREADCRUMB_FIELD_GUEST_RDX),
            0xeeeeeeee_ffffffff
        );
        assert_eq!(breadcrumb(3, BREADCRUMB_FIELD_DETAIL), 0x1234);
    }

    #[test]
    fn breadcrumb_rejects_out_of_range_queries() {
        reset_breadcrumbs_for_test();

        assert_eq!(breadcrumb(MAX_BREADCRUMB_CPUS as u64, 0), u64::MAX);
        assert_eq!(breadcrumb(0, BREADCRUMB_FIELD_LIMIT as u64), u64::MAX);
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
        10 => super::host_idt::HOST_IDT_PATCH_CALLS.load(Relaxed),
        11 => super::host_idt::HOST_IDT_PATCH_OK_CALLS.load(Relaxed),
        12 => super::host_idt::current_cpu_index() as u64,
        13 => super::host_idt::current_patch_mask(),
        14 => super::host_idt::current_host_idt_base(),
        15 => super::host_idt::current_host_idt_limit(),
        16 => super::support::vmread_checked(x86::vmx::vmcs::host::IDTR_BASE).unwrap_or(u64::MAX),
        17 => super::host_idt::current_nmi_target(),
        18 => super::host_idt::current_gp_target(),
        19 => super::host_idt::expected_nmi_handler(),
        20 => super::host_idt::expected_gp_handler(),
        21 => super::host_idt::current_mc_target(),
        22 => super::host_idt::expected_mc_handler(),
        23 => super::host_idt::HOST_MC_COUNT.load(Relaxed),
        24 => super::host_idt::MC_FAULT_RIP.load(Relaxed),
        25 => super::host_idt::current_pf_target(),
        26 => super::host_idt::expected_pf_handler(),
        27 => super::host_idt::HOST_PF_COUNT.load(Relaxed),
        28 => super::host_idt::PF_FAULT_RIP.load(Relaxed),
        29 => super::host_idt::PF_FAULT_CR2.load(Relaxed),
        _ => u64::MAX,
    }
}

#[cfg(test)]
pub fn reset_breadcrumbs_for_test() {
    for cpu in 0..MAX_BREADCRUMB_CPUS {
        BREADCRUMB_COUNT[cpu].store(0, Relaxed);
        BREADCRUMB_EXIT_REASON[cpu].store(0, Relaxed);
        BREADCRUMB_BASIC_REASON[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RIP[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RSP[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_CR3[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RFLAGS[cpu].store(0, Relaxed);
        BREADCRUMB_EXIT_QUAL[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RAX[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RCX[cpu].store(0, Relaxed);
        BREADCRUMB_GUEST_RDX[cpu].store(0, Relaxed);
        BREADCRUMB_DETAIL[cpu].store(0, Relaxed);
    }
}
