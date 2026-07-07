use {
    crate::{
        intel::{
            ept::paging::AccessType, invept::invept_all_contexts, support::vmread_checked,
            vmexit::ExitType, vmx::Vmx,
        },
        utils::capture::GuestRegisters,
    },
    wdk_sys::{
        _MM_COPY_ADDRESS__bindgen_ty_1, ntddk::MmCopyMemory, MM_COPY_ADDRESS,
        MM_COPY_MEMORY_PHYSICAL, NT_SUCCESS, PHYSICAL_ADDRESS,
    },
    x86::vmx::vmcs::guest,
};

pub const VMCALL_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
pub const CPUID_COMM_LEAF: u32 = 0x4000_0000;
const STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;
const STATUS_UNSUPPORTED_COMMAND: u64 = u64::MAX - 2;

const CMD_PING: u64 = 0x01;
const CMD_READ_PHYS: u64 = 0x10;
const CMD_WRITE_PHYS: u64 = 0x11;
const CMD_TRANSLATE_VA: u64 = 0x12;
const CMD_GET_GUEST_CR3: u64 = 0x13;
const CMD_GET_COUNTER: u64 = 0x14;
const CMD_GET_CTL: u64 = 0x15;
const CMD_SEAL_DIAGNOSTICS: u64 = 0x16;
const CMD_ARM_CLIENT_READS: u64 = 0x17;
const CMD_READ_PHYS_RESULT: u64 = 0x18;
const CMD_GET_BREADCRUMB: u64 = 0x19;
const CMD_GET_CLIENT_READ_STATE: u64 = 0x1A;
const CMD_READ_VIRT: u64 = 0x1B;
const CMD_READ_RESULT_INFO: u64 = 0x1C;
const CMD_READ_RESULT_WORD: u64 = 0x1D;
const CMD_RELEASE_READ_RESULT: u64 = 0x1E;
const CMD_READ_RESULT_QUAD: u64 = 0x1F;
const CMD_CLOAK_PAGE: u64 = 0x20;
const CMD_GET_RING: u64 = 0x25;
const CMD_REGISTER_BATCH_BUFFER: u64 = 0x26;
const CMD_UNREGISTER_BATCH_BUFFER: u64 = 0x27;
const CMD_GET_CPU_DIAG: u64 = 0x28;
const CMD_READ_CMOS_FREEZE: u64 = 0x29;
pub const CMD_DEVIRTUALIZE: u64 = 0xFF;
const CLIENT_READ_ARM_TOKEN: u64 = 0xC17E_A2D5_90B4_6F31;

const USER_CLIENT_READS_ENABLED: bool =
    user_client_read_flag_enabled(option_env!("HV_USER_CLIENT_READS"));

fn cs_selector_is_ring0(selector: u64) -> bool {
    selector & 0x3 == 0
}

const fn user_client_read_flag_enabled(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 1 && bytes[0] == b'1'
}

fn user_client_reads_are_enabled() -> bool {
    USER_CLIENT_READS_ENABLED
}

fn user_client_reads_are_armed() -> bool {
    crate::intel::diag::client_reads_armed()
}

fn user_client_read_command(cmd: u64) -> bool {
    matches!(
        cmd,
        CMD_READ_PHYS
            | CMD_READ_PHYS_RESULT
            | CMD_GET_GUEST_CR3
            | CMD_READ_VIRT
            | CMD_READ_RESULT_INFO
            | CMD_READ_RESULT_WORD
            | CMD_RELEASE_READ_RESULT
            | CMD_READ_RESULT_QUAD
            | CMD_REGISTER_BATCH_BUFFER
            | CMD_UNREGISTER_BATCH_BUFFER
    )
}

fn client_read_arm_token_is_valid(token: u64) -> bool {
    token == CLIENT_READ_ARM_TOKEN
}

fn command_requires_ring0(cmd: u64, arg1: u64) -> bool {
    command_requires_ring0_with_client_read_state(
        cmd,
        arg1,
        user_client_reads_are_enabled(),
        user_client_reads_are_armed(),
    )
}

fn command_requires_ring0_with_client_read_state(
    cmd: u64,
    arg1: u64,
    user_client_reads_enabled: bool,
    user_client_reads_armed: bool,
) -> bool {
    (user_client_read_command(cmd) && !(user_client_reads_enabled && user_client_reads_armed))
        || matches!(
            cmd,
            CMD_WRITE_PHYS | CMD_TRANSLATE_VA | CMD_CLOAK_PAGE | CMD_DEVIRTUALIZE
        )
        || (cmd == CMD_GET_CTL && matches!(arg1, 5 | 7))
}

fn diagnostic_command_allowed(cmd: u64, arg1: u64, sealed: bool) -> bool {
    diagnostic_command_allowed_with_client_read_state(
        cmd,
        arg1,
        sealed,
        user_client_reads_are_enabled(),
        user_client_reads_are_armed(),
    )
}

fn diagnostic_command_allowed_with_client_read_state(
    cmd: u64,
    arg1: u64,
    sealed: bool,
    user_client_reads_enabled: bool,
    user_client_reads_armed: bool,
) -> bool {
    !sealed
        || matches!(cmd, CMD_SEAL_DIAGNOSTICS | CMD_DEVIRTUALIZE)
        || (user_client_reads_enabled
            && cmd == CMD_ARM_CLIENT_READS
            && client_read_arm_token_is_valid(arg1))
        || (user_client_reads_enabled
            && user_client_reads_armed
            && (matches!(cmd, CMD_PING) || user_client_read_command(cmd)))
}

fn command_exit_type(cmd: u64) -> ExitType {
    match cmd {
        CMD_DEVIRTUALIZE => ExitType::ExitHypervisor,
        _ => ExitType::IncrementRIP,
    }
}

fn arm_client_reads_result(user_client_reads_enabled: bool, worker_started: bool) -> u64 {
    if user_client_reads_enabled && worker_started {
        0
    } else {
        STATUS_UNSUPPORTED_COMMAND
    }
}

fn physical_access_size_is_valid(size: usize) -> bool {
    (1..=8).contains(&size)
}

fn physical_writes_are_enabled() -> bool {
    false
}

fn physical_copy_address(pa: u64) -> MM_COPY_ADDRESS {
    MM_COPY_ADDRESS {
        __bindgen_anon_1: _MM_COPY_ADDRESS__bindgen_ty_1 {
            PhysicalAddress: PHYSICAL_ADDRESS {
                QuadPart: pa as i64,
            },
        },
    }
}

fn read_phys_sized(pa: u64, size: usize) -> Option<u64> {
    if !physical_access_size_is_valid(size) {
        return None;
    }

    let mut buffer = [0u8; 8];
    let mut bytes_transferred = 0u64;
    let status = unsafe {
        MmCopyMemory(
            buffer.as_mut_ptr().cast(),
            physical_copy_address(pa),
            size as u64,
            MM_COPY_MEMORY_PHYSICAL,
            &mut bytes_transferred,
        )
    };

    (NT_SUCCESS(status) && bytes_transferred == size as u64).then(|| u64::from_le_bytes(buffer))
}

fn read_page_table_entry(pa: u64) -> Option<u64> {
    read_phys_sized(pa, 8)
}

pub fn dispatch_command(guest_registers: &mut GuestRegisters, vmx: &mut Vmx) -> ExitType {
    let cmd = guest_registers.rcx;
    let arg1 = guest_registers.rdx;
    let arg2 = guest_registers.r8;
    let arg3 = guest_registers.r9;

    if !diagnostic_command_allowed(cmd, arg1, crate::intel::diag::diagnostics_sealed()) {
        guest_registers.rax = STATUS_ACCESS_DENIED;
        return ExitType::IncrementRIP;
    }

    if command_requires_ring0(cmd, arg1) {
        let guest_cs = match vmread_checked(guest::CS_SELECTOR) {
            Ok(value) => value,
            Err(error) => {
                log::error!("Failed to read guest CS selector for VMCALL: {:?}", error);
                guest_registers.rax = STATUS_ACCESS_DENIED;
                return ExitType::IncrementRIP;
            }
        };

        if !cs_selector_is_ring0(guest_cs) {
            guest_registers.rax = STATUS_ACCESS_DENIED;
            return ExitType::IncrementRIP;
        }
    }

    match cmd {
        CMD_PING => {
            guest_registers.rax = VMCALL_MAGIC;
            ExitType::IncrementRIP
        }
        CMD_READ_PHYS => {
            let pa = arg1;
            let size = arg2 as usize;
            guest_registers.rax =
                if user_client_reads_are_enabled() && user_client_reads_are_armed() {
                    crate::intel::client_read::submit_physical_read(pa, size)
                } else {
                    read_phys_sized(pa, size).unwrap_or(0)
                };
            ExitType::IncrementRIP
        }
        CMD_READ_PHYS_RESULT => {
            guest_registers.rax = crate::intel::client_read::poll_physical_read(arg1);
            ExitType::IncrementRIP
        }
        CMD_READ_RESULT_INFO => {
            guest_registers.rax = crate::intel::client_read::poll_read_info(arg1);
            ExitType::IncrementRIP
        }
        CMD_READ_RESULT_WORD => {
            guest_registers.rax = crate::intel::client_read::read_result_word(arg1, arg2);
            ExitType::IncrementRIP
        }
        CMD_READ_RESULT_QUAD => {
            let words = crate::intel::client_read::read_result_quad(arg1, arg2);
            guest_registers.rax = words[0];
            guest_registers.rbx = words[1];
            guest_registers.rcx = words[2];
            guest_registers.rdx = words[3];
            ExitType::IncrementRIP
        }
        CMD_REGISTER_BATCH_BUFFER => {
            guest_registers.rax =
                crate::intel::client_read::request_batch_buffer_registration(arg1, arg2 as usize);
            ExitType::IncrementRIP
        }
        CMD_UNREGISTER_BATCH_BUFFER => {
            guest_registers.rax = crate::intel::client_read::request_batch_buffer_unregister();
            ExitType::IncrementRIP
        }
        CMD_RELEASE_READ_RESULT => {
            guest_registers.rax = crate::intel::client_read::release_read_result(arg1);
            ExitType::IncrementRIP
        }
        CMD_READ_VIRT => {
            let cr3 = arg1;
            let va = arg2;
            let size = arg3 as usize;
            guest_registers.rax = crate::intel::client_read::submit_virtual_read(cr3, va, size);
            ExitType::IncrementRIP
        }
        CMD_WRITE_PHYS => {
            if physical_writes_are_enabled() {
                log::error!(
                    "Physical write VMCALL is enabled without a safe writer implementation"
                );
            }
            guest_registers.rax = STATUS_UNSUPPORTED_COMMAND;
            ExitType::IncrementRIP
        }
        CMD_TRANSLATE_VA => {
            let cr3 = arg1;
            let va = arg2;
            guest_registers.rax = translate_va_to_pa(cr3, va).unwrap_or(0);
            ExitType::IncrementRIP
        }
        CMD_GET_GUEST_CR3 => {
            guest_registers.rax = match vmread_checked(guest::CR3) {
                Ok(value) => value,
                Err(error) => {
                    log::error!("Failed to read guest CR3 for VMCALL: {:?}", error);
                    0
                }
            };
            ExitType::IncrementRIP
        }
        CMD_GET_COUNTER => {
            guest_registers.rax = crate::intel::diag::counter(arg1);
            ExitType::IncrementRIP
        }
        CMD_GET_CTL => {
            guest_registers.rax = crate::intel::diag::control(arg1);
            ExitType::IncrementRIP
        }
        CMD_GET_BREADCRUMB => {
            guest_registers.rax = crate::intel::diag::breadcrumb(arg1, arg2);
            ExitType::IncrementRIP
        }
        CMD_GET_RING => {
            guest_registers.rax = crate::intel::diag::ring_entry(arg1, arg2);
            ExitType::IncrementRIP
        }
        CMD_GET_CPU_DIAG => {
            guest_registers.rax = crate::intel::diag::cpu_diag(arg1, arg2);
            ExitType::IncrementRIP
        }
        CMD_READ_CMOS_FREEZE => {
            guest_registers.rax = crate::intel::diag::cmos_read_freeze(arg1);
            ExitType::IncrementRIP
        }
        CMD_GET_CLIENT_READ_STATE => {
            guest_registers.rax = crate::intel::client_read::debug_state(arg1);
            ExitType::IncrementRIP
        }
        CMD_SEAL_DIAGNOSTICS => {
            crate::intel::diag::seal_diagnostics();
            guest_registers.rax = 0;
            ExitType::IncrementRIP
        }
        CMD_ARM_CLIENT_READS => {
            let arm_result = arm_client_reads_result(
                user_client_reads_are_enabled(),
                crate::intel::client_read::worker_started(),
            );
            if arm_result == 0 {
                crate::intel::diag::arm_client_reads();
            }
            guest_registers.rax = arm_result;
            ExitType::IncrementRIP
        }
        CMD_CLOAK_PAGE => {
            let pa = arg1 & !0xFFF;
            let shared_data = vmx.shared_data_mut();
            let ept = &mut shared_data.primary_ept;

            let split_ok = ept
                .split_2mb_to_4kb(pa, AccessType::READ_WRITE_EXECUTE)
                .or_else(|e| {
                    if matches!(e, crate::error::HypervisorError::PageAlreadySplit) {
                        Ok(())
                    } else {
                        Err(e)
                    }
                });

            if split_ok.is_ok() {
                if ept.set_page_access(pa, AccessType::empty()).is_ok() {
                    invept_all_contexts();
                    guest_registers.rax = 0;
                } else {
                    guest_registers.rax = 2;
                }
            } else {
                guest_registers.rax = 1;
            }
            ExitType::IncrementRIP
        }
        CMD_DEVIRTUALIZE => {
            guest_registers.rax = 0;
            command_exit_type(cmd)
        }
        _ => {
            guest_registers.rax = u64::MAX;
            ExitType::IncrementRIP
        }
    }
}

fn translate_va_to_pa(cr3: u64, va: u64) -> Option<u64> {
    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;
    let offset = va & 0xFFF;

    let pml4e = read_page_table_entry(pml4_base + pml4_idx * 8)?;
    if pml4e & 1 == 0 {
        return None;
    }

    let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
    let pdpte = read_page_table_entry(pdpt_base + pdpt_idx * 8)?;
    if pdpte & 1 == 0 {
        return None;
    }
    if pdpte & 0x80 != 0 {
        return Some((pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF));
    }

    let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
    let pde = read_page_table_entry(pd_base + pd_idx * 8)?;
    if pde & 1 == 0 {
        return None;
    }
    if pde & 0x80 != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }

    let pt_base = pde & 0x000F_FFFF_FFFF_F000;
    let pte = read_page_table_entry(pt_base + pt_idx * 8)?;
    if pte & 1 == 0 {
        return None;
    }

    Some((pte & 0x000F_FFFF_FFFF_F000) | offset)
}

pub fn handle_vmcall(guest_registers: &mut GuestRegisters, vmx: &mut Vmx) -> Option<ExitType> {
    let guest_cpl = match vmread_checked(guest::CS_SELECTOR) {
        Ok(selector) => selector & 0x3,
        Err(error) => {
            log::error!(
                "Failed to read guest CS selector for VMCALL auth: {:?}",
                error
            );
            return None;
        }
    };

    if !vmcall_authorized_for_cpl(guest_registers, guest_cpl) {
        return None;
    }
    Some(dispatch_command(guest_registers, vmx))
}

fn vmcall_authorized(guest_registers: &GuestRegisters) -> bool {
    guest_registers.rax == VMCALL_MAGIC
        && guest_registers.r10 == VMCALL_MAGIC
        && guest_registers.r11 == VMCALL_MAGIC
}

fn vmcall_authorized_for_cpl(guest_registers: &GuestRegisters, guest_cpl: u64) -> bool {
    guest_cpl == 0 && vmcall_authorized(guest_registers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring0_selector_is_privileged() {
        assert!(cs_selector_is_ring0(0x10));
        assert!(!cs_selector_is_ring0(0x33));
    }

    #[test]
    fn physical_access_size_must_fit_native_read_width() {
        assert!(physical_access_size_is_valid(1));
        assert!(physical_access_size_is_valid(8));
        assert!(!physical_access_size_is_valid(0));
        assert!(!physical_access_size_is_valid(9));
    }

    #[test]
    fn physical_write_command_is_disabled_by_default() {
        assert!(!physical_writes_are_enabled());
    }

    #[test]
    fn user_client_reads_are_disabled_by_default() {
        assert!(!user_client_reads_are_enabled());
    }

    #[test]
    fn user_client_read_flag_accepts_only_one() {
        assert!(user_client_read_flag_enabled(Some("1")));
        assert!(!user_client_read_flag_enabled(None));
        assert!(!user_client_read_flag_enabled(Some("")));
        assert!(!user_client_read_flag_enabled(Some("0")));
        assert!(!user_client_read_flag_enabled(Some("true")));
    }

    #[test]
    fn dangerous_commands_require_ring0() {
        assert!(!command_requires_ring0(CMD_PING, 0));
        assert!(!command_requires_ring0(CMD_GET_COUNTER, 0));
        assert!(!command_requires_ring0(CMD_GET_CTL, 0));
        assert!(command_requires_ring0(CMD_GET_GUEST_CR3, 0));
        assert!(command_requires_ring0(CMD_READ_PHYS, 0));
        assert!(command_requires_ring0(CMD_TRANSLATE_VA, 0));
        assert!(command_requires_ring0(CMD_GET_CTL, 5));
        assert!(command_requires_ring0(CMD_GET_CTL, 7));
        assert!(command_requires_ring0(CMD_WRITE_PHYS, 0));
        assert!(command_requires_ring0(CMD_CLOAK_PAGE, 0));
        assert!(command_requires_ring0(CMD_DEVIRTUALIZE, 0));
    }

    #[test]
    fn client_read_build_allows_user_read_commands_only() {
        assert!(!command_requires_ring0_with_client_read_state(
            CMD_READ_PHYS,
            0,
            true,
            true
        ));
        assert!(!command_requires_ring0_with_client_read_state(
            CMD_READ_PHYS_RESULT,
            0,
            true,
            true
        ));
        assert!(!command_requires_ring0_with_client_read_state(
            CMD_READ_RESULT_QUAD,
            0,
            true,
            true
        ));
        assert!(!command_requires_ring0_with_client_read_state(
            CMD_READ_VIRT,
            0,
            true,
            true
        ));
        assert!(command_requires_ring0_with_client_read_state(
            CMD_TRANSLATE_VA,
            0,
            true,
            true
        ));
        assert!(!command_requires_ring0_with_client_read_state(
            CMD_GET_GUEST_CR3,
            0,
            true,
            true
        ));
        assert!(command_requires_ring0_with_client_read_state(
            CMD_WRITE_PHYS,
            0,
            true,
            true
        ));
        assert!(command_requires_ring0_with_client_read_state(
            CMD_CLOAK_PAGE,
            0,
            true,
            true
        ));
        assert!(command_requires_ring0_with_client_read_state(
            CMD_DEVIRTUALIZE,
            0,
            true,
            true
        ));
    }

    #[test]
    fn client_read_build_allows_batch_buffer_commands() {
        assert_eq!(CMD_REGISTER_BATCH_BUFFER, 0x26);
        assert_eq!(CMD_UNREGISTER_BATCH_BUFFER, 0x27);
        assert!(!command_requires_ring0_with_client_read_state(
            CMD_REGISTER_BATCH_BUFFER,
            0,
            true,
            true
        ));
        assert!(!command_requires_ring0_with_client_read_state(
            CMD_UNREGISTER_BATCH_BUFFER,
            0,
            true,
            true
        ));
    }

    #[test]
    fn client_read_build_requires_runtime_arm() {
        assert!(command_requires_ring0_with_client_read_state(
            CMD_READ_PHYS,
            0,
            true,
            false
        ));
        assert!(!command_requires_ring0_with_client_read_state(
            CMD_READ_PHYS,
            0,
            true,
            true
        ));
    }

    #[test]
    fn vmcall_requires_auth_token() {
        let mut regs = GuestRegisters::default();
        regs.rax = VMCALL_MAGIC;
        assert!(!vmcall_authorized(&regs));

        regs.r10 = VMCALL_MAGIC;
        assert!(!vmcall_authorized(&regs));

        regs.r11 = VMCALL_MAGIC;
        assert!(vmcall_authorized(&regs));
    }

    #[test]
    fn vmcall_requires_ring0_even_with_auth_token() {
        let mut regs = GuestRegisters::default();
        regs.rax = VMCALL_MAGIC;
        regs.r10 = VMCALL_MAGIC;
        regs.r11 = VMCALL_MAGIC;

        assert!(!vmcall_authorized_for_cpl(&regs, 3));
        assert!(vmcall_authorized_for_cpl(&regs, 0));
    }

    #[test]
    fn sealed_diagnostics_deny_user_visible_ping_magic() {
        assert!(!diagnostic_command_allowed(CMD_PING, 0, true));
        assert!(!diagnostic_command_allowed(CMD_GET_GUEST_CR3, 0, true));
        assert!(!diagnostic_command_allowed(CMD_READ_PHYS, 0, true));
        assert!(!diagnostic_command_allowed(CMD_TRANSLATE_VA, 0, true));
        assert!(diagnostic_command_allowed(CMD_SEAL_DIAGNOSTICS, 0, true));
        assert!(diagnostic_command_allowed(CMD_DEVIRTUALIZE, 0, true));
        assert!(!diagnostic_command_allowed(CMD_GET_COUNTER, 0, true));
        assert!(!diagnostic_command_allowed(CMD_GET_CTL, 1, true));
        assert!(!diagnostic_command_allowed(CMD_GET_CTL, 8, true));

        assert!(diagnostic_command_allowed(CMD_GET_COUNTER, 0, false));
        assert!(diagnostic_command_allowed(CMD_GET_CTL, 1, false));
    }

    #[test]
    fn breadcrumb_command_is_diagnostic_only() {
        assert!(diagnostic_command_allowed(CMD_GET_BREADCRUMB, 0, false));
        assert!(!diagnostic_command_allowed(CMD_GET_BREADCRUMB, 0, true));
        assert!(!command_requires_ring0(CMD_GET_BREADCRUMB, 0));
    }

    #[test]
    fn client_read_state_command_is_diagnostic_only() {
        assert!(diagnostic_command_allowed(
            CMD_GET_CLIENT_READ_STATE,
            0,
            false
        ));
        assert!(!diagnostic_command_allowed(
            CMD_GET_CLIENT_READ_STATE,
            0,
            true
        ));
        assert!(!command_requires_ring0(CMD_GET_CLIENT_READ_STATE, 0));
    }

    #[test]
    fn arm_client_reads_requires_worker_started() {
        assert_eq!(arm_client_reads_result(true, true), 0);
        assert_eq!(
            arm_client_reads_result(true, false),
            STATUS_UNSUPPORTED_COMMAND
        );
        assert_eq!(
            arm_client_reads_result(false, true),
            STATUS_UNSUPPORTED_COMMAND
        );
    }

    #[test]
    fn sealed_client_read_build_keeps_user_client_channel_available() {
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_PING, 0, true, true, true
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_GET_GUEST_CR3,
            0,
            true,
            true,
            true
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_READ_PHYS,
            0,
            true,
            true,
            true
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_READ_PHYS_RESULT,
            0,
            true,
            true,
            true
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_READ_RESULT_QUAD,
            0,
            true,
            true,
            true
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_READ_VIRT,
            0,
            true,
            true,
            true
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_REGISTER_BATCH_BUFFER,
            0,
            true,
            true,
            true
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_UNREGISTER_BATCH_BUFFER,
            0,
            true,
            true,
            true
        ));
        assert!(!diagnostic_command_allowed_with_client_read_state(
            CMD_TRANSLATE_VA,
            0,
            true,
            true,
            true
        ));
        assert!(!diagnostic_command_allowed_with_client_read_state(
            CMD_GET_COUNTER,
            0,
            true,
            true,
            true
        ));
        assert!(!diagnostic_command_allowed_with_client_read_state(
            CMD_GET_CTL,
            1,
            true,
            true,
            true
        ));
    }

    #[test]
    fn sealed_client_read_build_matches_stable_until_armed() {
        assert!(!diagnostic_command_allowed_with_client_read_state(
            CMD_ARM_CLIENT_READS,
            0,
            true,
            true,
            false
        ));
        assert!(!diagnostic_command_allowed_with_client_read_state(
            CMD_PING, 0, true, true, false
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_PING, 0, true, true, true
        ));
        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_READ_PHYS,
            0,
            true,
            true,
            true
        ));
    }

    #[test]
    fn sealed_client_read_build_allows_tokened_arm_after_startup() {
        const TEST_ARM_TOKEN: u64 = 0xC17E_A2D5_90B4_6F31;

        assert!(diagnostic_command_allowed_with_client_read_state(
            CMD_ARM_CLIENT_READS,
            TEST_ARM_TOKEN,
            true,
            true,
            false
        ));
    }

    #[test]
    fn devirtualize_command_exits_hypervisor() {
        assert_eq!(
            command_exit_type(CMD_DEVIRTUALIZE),
            ExitType::ExitHypervisor
        );
        assert_eq!(command_exit_type(CMD_PING), ExitType::IncrementRIP);
    }
}
