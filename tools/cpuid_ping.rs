use std::arch::asm;

const CPUID_LEAF: u64 = 0x4000_0000;
const LEGACY_CPUID_LEAF: u64 = 0x7A3F_E1D9;
const EXPECTED_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const HV_STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;
const CMD_PING: u64 = 0x01;
const CMD_GET_COUNTER: u64 = 0x14;
const CMD_SEAL_DIAGNOSTICS: u64 = 0x16;
const CMD_GET_CTL: u64 = 0x15;
const HOST_IDT_PATCH_ALL: u64 = 0x3F;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_response_marks_diagnostics_as_sealed() {
        assert!(diagnostics_access_denied(HV_STATUS_ACCESS_DENIED));
        assert!(!diagnostics_access_denied(EXPECTED_MAGIC));
        assert!(!diagnostics_access_denied(0));
    }

    #[test]
    fn seal_verification_requires_success_and_denied_probe() {
        assert!(seal_verification_passed(0, HV_STATUS_ACCESS_DENIED));
        assert!(!seal_verification_passed(0, 0));
        assert!(!seal_verification_passed(1, HV_STATUS_ACCESS_DENIED));
    }

    #[test]
    fn status_report_names_active_and_inactive_states() {
        assert_eq!(status_report(EXPECTED_MAGIC, 0), ("[+] HV active", 0));
        assert_eq!(
            status_report(HV_STATUS_ACCESS_DENIED, 0),
            ("[+] HV active (diagnostics sealed)", 0)
        );
        assert_eq!(
            status_report(0, EXPECTED_MAGIC),
            ("[+] HV active (legacy leaf)", 0)
        );
        assert_eq!(status_report(0, 0), ("[-] HV inactive", 2));
    }

    #[test]
    fn cpuid_zero_check_requires_all_registers_zero() {
        assert!(cpuid_result_is_zero((0, 0, 0, 0)));
        assert!(!cpuid_result_is_zero((0, 0, 1, 0)));
    }

    #[test]
    fn host_idt_patch_check_requires_all_runtime_evidence() {
        assert!(host_idt_patch_ok(
            24,
            24,
            HOST_IDT_PATCH_ALL,
            0x1000,
            0x1000,
            0x2000,
            0x2000,
            0x3000,
            0x3000,
            0x4000,
            0x4000,
            0x5000,
            0x5000,
        ));
        assert!(!host_idt_patch_ok(
            0,
            0,
            HOST_IDT_PATCH_ALL,
            0x1000,
            0x1000,
            0x2000,
            0x2000,
            0x3000,
            0x3000,
            0x4000,
            0x4000,
            0x5000,
            0x5000,
        ));
        assert!(!host_idt_patch_ok(
            24,
            23,
            HOST_IDT_PATCH_ALL,
            0x1000,
            0x1000,
            0x2000,
            0x2000,
            0x3000,
            0x3000,
            0x4000,
            0x4000,
            0x5000,
            0x5000,
        ));
        assert!(!host_idt_patch_ok(
            24, 24, 0x1f, 0x1000, 0x1000, 0x2000, 0x2000, 0x3000, 0x3000, 0x4000, 0x4000, 0x5000,
            0x5000,
        ));
        assert!(!host_idt_patch_ok(
            24,
            24,
            HOST_IDT_PATCH_ALL,
            0x1000,
            0x4000,
            0x2000,
            0x2000,
            0x3000,
            0x3000,
            0x4000,
            0x4000,
            0x5000,
            0x5000,
        ));
        assert!(!host_idt_patch_ok(
            24,
            24,
            HOST_IDT_PATCH_ALL,
            0x1000,
            0x1000,
            0x2001,
            0x2000,
            0x3000,
            0x3000,
            0x4000,
            0x4000,
            0x5000,
            0x5000,
        ));
        assert!(!host_idt_patch_ok(
            24,
            24,
            HOST_IDT_PATCH_ALL,
            0x1000,
            0x1000,
            0x2000,
            0x2000,
            0x3000,
            0x3000,
            0x4001,
            0x4000,
            0x5000,
            0x5000,
        ));
        assert!(!host_idt_patch_ok(
            24,
            24,
            HOST_IDT_PATCH_ALL,
            0x1000,
            0x1000,
            0x2000,
            0x2000,
            0x3000,
            0x3000,
            0x4000,
            0x4000,
            0x5001,
            0x5000,
        ));
    }
}

fn hv_cmd(cmd: u64, arg1: u64) -> u64 {
    cpuid_cmd(CPUID_LEAF, cmd, arg1, EXPECTED_MAGIC)
}

fn hv_cmd_unauth(cmd: u64, arg1: u64) -> u64 {
    cpuid_cmd(CPUID_LEAF, cmd, arg1, 0)
}

fn legacy_hv_cmd(cmd: u64, arg1: u64) -> u64 {
    cpuid_cmd(LEGACY_CPUID_LEAF, cmd, arg1, EXPECTED_MAGIC)
}

fn diagnostics_access_denied(value: u64) -> bool {
    value == HV_STATUS_ACCESS_DENIED
}

fn seal_verification_passed(seal_result: u64, probe_result: u64) -> bool {
    seal_result == 0 && diagnostics_access_denied(probe_result)
}

fn status_report(current_leaf: u64, legacy_leaf: u64) -> (&'static str, i32) {
    if current_leaf == EXPECTED_MAGIC {
        ("[+] HV active", 0)
    } else if diagnostics_access_denied(current_leaf) {
        ("[+] HV active (diagnostics sealed)", 0)
    } else if legacy_leaf == EXPECTED_MAGIC {
        ("[+] HV active (legacy leaf)", 0)
    } else if diagnostics_access_denied(legacy_leaf) {
        ("[+] HV active (legacy leaf, diagnostics sealed)", 0)
    } else {
        ("[-] HV inactive", 2)
    }
}

fn host_idt_patch_ok(
    calls: u64,
    ok_calls: u64,
    current_mask: u64,
    host_base: u64,
    vmcs_base: u64,
    nmi_target: u64,
    nmi_expected: u64,
    gp_target: u64,
    gp_expected: u64,
    mc_target: u64,
    mc_expected: u64,
    pf_target: u64,
    pf_expected: u64,
) -> bool {
    calls != 0
        && ok_calls == calls
        && (current_mask & HOST_IDT_PATCH_ALL) == HOST_IDT_PATCH_ALL
        && host_base != 0
        && host_base == vmcs_base
        && nmi_target == nmi_expected
        && gp_target == gp_expected
        && mc_target == mc_expected
        && pf_target == pf_expected
}

fn cpuid_result_is_zero(result: (u32, u32, u32, u32)) -> bool {
    result.0 == 0 && result.1 == 0 && result.2 == 0 && result.3 == 0
}

fn cpuid_cmd(leaf: u64, cmd: u64, arg1: u64, token: u64) -> u64 {
    let result: u64;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("rax") leaf => result,
            inlateout("rcx") cmd => _,
            inlateout("rdx") arg1 => _,
            in("r8") 0u64,
            in("r9") 0u64,
            in("r10") token,
            in("r11") token,
        );
    }
    result
}

fn guest_cpuid(leaf: u32, sub_leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        asm!(
            "push rbx",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inlateout("eax") leaf => eax,
            inlateout("ecx") sub_leaf => ecx,
            lateout("edx") edx,
            ebx_out = lateout(reg) ebx,
            lateout("r10") _,
            lateout("r11") _,
        );
    }
    (eax, ebx, ecx, edx)
}

fn main() {
    let status_only = std::env::args().any(|arg| arg == "--status");
    let seal_only = std::env::args().any(|arg| arg == "--seal");
    let r = hv_cmd(CMD_PING, 0);

    if status_only {
        let legacy = legacy_hv_cmd(CMD_PING, 0);
        let (message, code) = status_report(r, legacy);
        println!("{}", message);
        std::process::exit(code);
    }

    println!("[*] CPUID Hypervisor Ping (leaf 0x{:X})", CPUID_LEAF);

    let diagnostics_sealed_by_ping = diagnostics_access_denied(r);

    if r != EXPECTED_MAGIC && !diagnostics_sealed_by_ping {
        println!("[-] no HV. got 0x{:X}", r);
        std::process::exit(2);
    }
    if diagnostics_sealed_by_ping {
        println!("[+] HV alive (diagnostics sealed)");
    } else {
        println!("[+] HV alive! magic=0x{:X}", r);
    }

    if seal_only {
        if diagnostics_sealed_by_ping {
            println!("[+] diagnostic channel already sealed");
            std::process::exit(0);
        }
        let sealed = hv_cmd(CMD_SEAL_DIAGNOSTICS, 0);
        let probe = hv_cmd(CMD_GET_COUNTER, 0);
        if seal_verification_passed(sealed, probe) {
            println!("[+] diagnostic channel sealed");
            std::process::exit(0);
        }
        println!(
            "[-] failed to seal diagnostic channel: seal=0x{:X} probe=0x{:X}",
            sealed, probe
        );
        std::process::exit(1);
    }

    let mut checks_ok = true;

    let unauth = hv_cmd_unauth(0x01, 0);
    if unauth == 0 {
        println!("[+] unauth CPUID leaf hidden");
    } else {
        println!("[!] unauth CPUID leaf leaked 0x{:X}", unauth);
        checks_ok = false;
    }

    println!("\n=== Guest-visible CPUID ===");
    let (_, _, feature_ecx, _) = guest_cpuid(1, 0);
    println!(
        "  Leaf 1 ECX      = {:#010x} hypervisor={} vmx={} smx={}",
        feature_ecx,
        (feature_ecx >> 31) & 1,
        (feature_ecx >> 5) & 1,
        (feature_ecx >> 6) & 1
    );
    let (_, leaf7_ebx, leaf7_ecx, _) = guest_cpuid(7, 0);
    println!(
        "  Leaf 7          = ebx={:#010x} ecx={:#010x} sgx={} intel_pt={} waitpkg={} sgx_lc={}",
        leaf7_ebx,
        leaf7_ecx,
        (leaf7_ebx >> 2) & 1,
        (leaf7_ebx >> 25) & 1,
        (leaf7_ecx >> 5) & 1,
        (leaf7_ecx >> 30) & 1
    );
    let (hv_max, hv_ebx, hv_ecx, hv_edx) = guest_cpuid(0x4000_0000, 0);
    println!(
        "  Leaf 40000000   = eax={:#010x} ebx={:#010x} ecx={:#010x} edx={:#010x}",
        hv_max, hv_ebx, hv_ecx, hv_edx
    );
    let hidden_hv_ext = guest_cpuid(0x4000_0100, 0);
    println!(
        "  Leaf 40000100   = eax={:#010x} ebx={:#010x} ecx={:#010x} edx={:#010x}",
        hidden_hv_ext.0, hidden_hv_ext.1, hidden_hv_ext.2, hidden_hv_ext.3
    );
    let (sgx_eax, sgx_ebx, sgx_ecx, sgx_edx) = guest_cpuid(0x12, 0);
    println!(
        "  Leaf 12         = eax={:#010x} ebx={:#010x} ecx={:#010x} edx={:#010x}",
        sgx_eax, sgx_ebx, sgx_ecx, sgx_edx
    );
    if ((feature_ecx >> 31) & 1) == 0
        && ((feature_ecx >> 5) & 1) == 0
        && ((feature_ecx >> 6) & 1) == 0
        && ((leaf7_ebx >> 2) & 1) == 0
        && ((leaf7_ebx >> 25) & 1) == 0
        && ((leaf7_ecx >> 5) & 1) == 0
        && ((leaf7_ecx >> 30) & 1) == 0
        && hv_max == 0
        && hv_ebx == 0
        && hv_ecx == 0
        && hv_edx == 0
        && cpuid_result_is_zero(hidden_hv_ext)
        && sgx_eax == 0
        && sgx_ebx == 0
        && sgx_ecx == 0
        && sgx_edx == 0
    {
        println!("  Masking         = OK");
    } else {
        println!("  Masking         = CHECK");
        checks_ok = false;
    }

    if diagnostics_sealed_by_ping {
        println!("\n=== Diagnostics ===");
        println!("  sealed          = yes");
        println!("  VMCS controls   = skipped");
        println!("  Exit counters   = skipped");
        if !checks_ok {
            std::process::exit(1);
        }
        return;
    }

    println!("\n=== VMCS Controls ===");
    let names = ["Pin-based", "Primary", "Secondary", "VM-exit", "VM-entry"];
    let mut primary = 0;
    let mut secondary = 0;
    let mut exit = 0;
    let mut entry = 0;
    let mut diagnostics_sealed = false;
    for (i, name) in names.iter().enumerate() {
        let v = hv_cmd(CMD_GET_CTL, i as u64);
        if diagnostics_access_denied(v) {
            println!("  {:<12} = access denied (diagnostics sealed)", name);
            diagnostics_sealed = true;
            break;
        }
        if i == 1 {
            primary = v;
        } else if i == 2 {
            secondary = v;
        } else if i == 3 {
            exit = v;
        } else if i == 4 {
            entry = v;
        }
        println!("  {:<12} = {:#010x}", name, v);
        if i == 0 {
            println!(
                "    bit0 ExtIntExit={} bit3 NmiExit={} bit5 VirtNmi={} bit6 Preempt={}",
                v & 1,
                (v >> 3) & 1,
                (v >> 5) & 1,
                (v >> 6) & 1
            );
        } else if i == 1 {
            println!(
                "    bit3 TscOffset={} bit12 RdtscExit={} bit28 MsrBitmap={} bit31 Secondary={}",
                (v >> 3) & 1,
                (v >> 12) & 1,
                (v >> 28) & 1,
                (v >> 31) & 1
            );
        } else if i == 2 {
            println!("    bit19 ConcealVmxFromPt={}", (v >> 19) & 1);
        } else if i == 3 {
            println!("    bit24 ConcealVmxFromPt={}", (v >> 24) & 1);
        } else if i == 4 {
            println!("    bit17 ConcealVmxFromPt={}", (v >> 17) & 1);
        }
    }

    if diagnostics_sealed {
        println!("\n=== Diagnostics ===");
        println!("  sealed          = yes");
        println!("  VMCS controls   = skipped");
        println!("  Exit counters   = skipped");
        if !checks_ok {
            std::process::exit(1);
        }
        return;
    }

    println!("\n=== Exit Counters ===");
    let counter_names = [
        "Total",
        "CPUID",
        "ExtInt",
        "Exception",
        "EPT Viol",
        "EPT Misconfig",
        "CR Access",
        "XSETBV",
        "Other",
        "MSR",
        "Host #GP",
        "Host NMI",
        "LastMsrAddr",
        "LastMsrAction",
        "MsrReadCnt",
        "MsrWriteCnt",
        "MsrGpInject",
        "LastHandlerID",
        "LastHandlerDet",
        "Host #PF",
        "Host #MC",
        "RDTSC",
        "VMX Instr",
    ];
    for (i, name) in counter_names.iter().enumerate() {
        let v = hv_cmd(0x14, i as u64);
        if v > 0 || i == 0 {
            if i == 12 || i == 18 {
                println!("  {:<14} = {:#x}", name, v);
            } else {
                println!("  {:<14} = {}", name, v);
            }
        }
    }

    let last = hv_cmd(CMD_GET_CTL, 6);
    println!("  LastExitReason = {:#x}", last);

    let gp_rip = hv_cmd(CMD_GET_CTL, 7);
    if gp_rip != 0 && gp_rip != u64::MAX && gp_rip != HV_STATUS_ACCESS_DENIED {
        println!("  GP_FAULT_RIP   = {:#x}", gp_rip);
    }

    let tsc_offset = hv_cmd(CMD_GET_CTL, 8);
    if tsc_offset == u64::MAX {
        println!("  TSC_OFFSET     = unsupported by loaded HV");
        checks_ok = false;
    } else {
        println!("  TSC_OFFSET     = {:#x}", tsc_offset);
    }

    let boot_stage = hv_cmd(CMD_GET_CTL, 9);
    if boot_stage != u64::MAX && boot_stage != HV_STATUS_ACCESS_DENIED {
        println!("  BOOT_STAGE     = {}", boot_stage);
    }

    println!("\n=== Host IDT Patch ===");
    let patch_calls = hv_cmd(CMD_GET_CTL, 10);
    let patch_ok_calls = hv_cmd(CMD_GET_CTL, 11);
    let current_cpu = hv_cmd(CMD_GET_CTL, 12);
    let current_mask = hv_cmd(CMD_GET_CTL, 13);
    let host_idtr_base = hv_cmd(CMD_GET_CTL, 14);
    let host_idtr_limit = hv_cmd(CMD_GET_CTL, 15);
    let vmcs_host_idtr_base = hv_cmd(CMD_GET_CTL, 16);
    let nmi_target = hv_cmd(CMD_GET_CTL, 17);
    let gp_target = hv_cmd(CMD_GET_CTL, 18);
    let nmi_expected = hv_cmd(CMD_GET_CTL, 19);
    let gp_expected = hv_cmd(CMD_GET_CTL, 20);
    let mc_target = hv_cmd(CMD_GET_CTL, 21);
    let mc_expected = hv_cmd(CMD_GET_CTL, 22);
    let host_mc_count = hv_cmd(CMD_GET_CTL, 23);
    let mc_fault_rip = hv_cmd(CMD_GET_CTL, 24);
    let pf_target = hv_cmd(CMD_GET_CTL, 25);
    let pf_expected = hv_cmd(CMD_GET_CTL, 26);
    let host_pf_count = hv_cmd(CMD_GET_CTL, 27);
    let pf_fault_rip = hv_cmd(CMD_GET_CTL, 28);
    let pf_fault_cr2 = hv_cmd(CMD_GET_CTL, 29);

    if patch_calls == u64::MAX
        || current_mask == u64::MAX
        || host_idtr_base == u64::MAX
        || vmcs_host_idtr_base == u64::MAX
        || mc_target == u64::MAX
        || pf_target == u64::MAX
    {
        println!("  Status         = unsupported by loaded HV");
        checks_ok = false;
    } else {
        println!("  Calls          = {} ok={}", patch_calls, patch_ok_calls);
        println!(
            "  Current CPU    = {} mask={:#x} required={:#x}",
            current_cpu, current_mask, HOST_IDT_PATCH_ALL
        );
        println!(
            "  HOST_IDTR      = base={:#x} limit={:#x} vmcs_base={:#x}",
            host_idtr_base, host_idtr_limit, vmcs_host_idtr_base
        );
        println!(
            "  NMI handler    = target={:#x} expected={:#x}",
            nmi_target, nmi_expected
        );
        println!(
            "  #GP handler    = target={:#x} expected={:#x}",
            gp_target, gp_expected
        );
        println!(
            "  #PF handler    = target={:#x} expected={:#x}",
            pf_target, pf_expected
        );
        println!(
            "  #MC handler    = target={:#x} expected={:#x}",
            mc_target, mc_expected
        );
        println!(
            "  Host #MC       = count={} rip={:#x}",
            host_mc_count, mc_fault_rip
        );
        println!(
            "  Host #PF       = count={} rip={:#x} cr2={:#x}",
            host_pf_count, pf_fault_rip, pf_fault_cr2
        );

        if host_idt_patch_ok(
            patch_calls,
            patch_ok_calls,
            current_mask,
            host_idtr_base,
            vmcs_host_idtr_base,
            nmi_target,
            nmi_expected,
            gp_target,
            gp_expected,
            mc_target,
            mc_expected,
            pf_target,
            pf_expected,
        ) {
            println!("  Status         = OK");
        } else {
            println!("  Status         = CHECK");
            checks_ok = false;
        }
    }

    if ((primary >> 3) & 1) == 0 {
        println!("\n[i] dynamic TSC offsetting disabled for stable clock");
    }

    if ((secondary >> 19) & 1) != 0 && ((exit >> 24) & 1) != 0 && ((entry >> 17) & 1) != 0 {
        println!("[+] Intel PT VMX concealment enabled");
    } else {
        println!("[i] Intel PT VMX concealment unavailable or not enabled");
    }

    if ((secondary >> 15) & 1) != 0 && ((secondary >> 28) & 1) != 0 {
        println!("[+] SGX ENCLS/ENCLV exiting enabled");
    } else {
        println!("[i] SGX ENCLS/ENCLV exiting unavailable or not enabled");
    }

    if !checks_ok {
        std::process::exit(1);
    }
}
