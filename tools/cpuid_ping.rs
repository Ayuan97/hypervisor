use std::arch::asm;

const CPUID_LEAF: u64 = 0x4000_0000;
const LEGACY_CPUID_LEAF: u64 = 0x7A3F_E1D9;
const EXPECTED_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const HV_STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;
const CMD_PING: u64 = 0x01;
const CMD_GET_COUNTER: u64 = 0x14;
const CMD_SEAL_DIAGNOSTICS: u64 = 0x16;
const CMD_GET_CTL: u64 = 0x15;
const CMD_GET_RING: u64 = 0x25;
const CMD_GET_BREADCRUMB: u64 = 0x19;
const CMD_GET_CPU_DIAG: u64 = 0x28;
const CMD_READ_CMOS_FREEZE: u64 = 0x29;
const HOST_IDT_PATCH_ALL: u64 = 0x3F;
const MAX_TRACKED_CPUS: u64 = 64;

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
    cpuid_cmd2(leaf, cmd, arg1, 0, token)
}

fn cpuid_cmd2(leaf: u64, cmd: u64, arg1: u64, arg2: u64, token: u64) -> u64 {
    let result: u64;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("rax") leaf => result,
            inlateout("rcx") cmd => _,
            inlateout("rdx") arg1 => _,
            in("r8") arg2,
            in("r9") 0u64,
            in("r10") token,
            in("r11") token,
        );
    }
    result
}

fn hv_ring(slot: u64, field: u64) -> u64 {
    cpuid_cmd2(CPUID_LEAF, CMD_GET_RING, slot, field, EXPECTED_MAGIC)
}

fn hv_cpu_diag(cpu: u64, field: u64) -> u64 {
    cpuid_cmd2(CPUID_LEAF, CMD_GET_CPU_DIAG, cpu, field, EXPECTED_MAGIC)
}

fn hv_breadcrumb(cpu: u64, field: u64) -> u64 {
    cpuid_cmd2(CPUID_LEAF, CMD_GET_BREADCRUMB, cpu, field, EXPECTED_MAGIC)
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
        "RingWriteIdx",
        "Preempt Timer",
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
        let host_gp_count = hv_cmd(CMD_GET_COUNTER, 10);
        let host_nmi_count = hv_cmd(CMD_GET_COUNTER, 11);
        println!(
            "  Host #GP       = count={} rip={:#x}",
            host_gp_count, gp_rip
        );
        println!(
            "  Host NMI       = count={}",
            host_nmi_count
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

    let ring_idx = hv_cmd(CMD_GET_COUNTER, 23);
    if ring_idx != u64::MAX {
        println!("\n=== VM-Exit Ring Buffer (last 32, filtered) ===");
        println!("  Write index    = {}", ring_idx);
        let count = if ring_idx < 32 { ring_idx } else { 32 };
        let start = if ring_idx >= 32 { ring_idx - 32 } else { 0 };
        for i in 0..count {
            let slot = ((start + i) % 32) as u64;
            let reason = hv_ring(slot, 0);
            let rip = hv_ring(slot, 1);
            let qual = hv_ring(slot, 2);
            let rax = hv_ring(slot, 3);
            if reason == 0 && rip == 0 { continue; }
            println!(
                "  [{}] reason={:<3} rip={:#018x} qual={:#x} rax={:#x}",
                slot, reason, rip, qual, rax
            );
        }
    }

    println!("\n=== Per-CPU Heartbeat ===");
    let mut any_active = false;
    for cpu in 0..MAX_TRACKED_CPUS {
        let heartbeat = hv_cpu_diag(cpu, 0);
        let phase = hv_cpu_diag(cpu, 1);
        let last_leaf = hv_cpu_diag(cpu, 2);
        let timer_rip = hv_cpu_diag(cpu, 3);
        let timer_stuck = hv_cpu_diag(cpu, 4);
        if heartbeat == u64::MAX { break; }
        if heartbeat > 0 {
            any_active = true;
            if timer_stuck > 2 {
                println!(
                    "  CPU {:>2}  heartbeat={:<10} phase={:#04x} leaf={:#x} STUCK_RIP={:#x} ({})",
                    cpu, heartbeat, phase, last_leaf, timer_rip, timer_stuck
                );
            } else {
                println!(
                    "  CPU {:>2}  heartbeat={:<10} phase={:#04x} leaf={:#x} rip={:#x}",
                    cpu, heartbeat, phase, last_leaf, timer_rip
                );
            }
        }
    }
    if !any_active {
        println!("  (no active CPUs)");
    }

    // Per-CPU breadcrumbs: last VM-exit guest state (captured by preemption timer)
    println!("\n=== Per-CPU Breadcrumb (last slow-path VM-exit) ===");
    let mut any_breadcrumb = false;
    for cpu in 0..MAX_TRACKED_CPUS {
        let count = hv_breadcrumb(cpu, 0);
        if count == u64::MAX || count == 0 { continue; }
        any_breadcrumb = true;
        let exit_reason = hv_breadcrumb(cpu, 1);
        let guest_rip = hv_breadcrumb(cpu, 3);
        let guest_rsp = hv_breadcrumb(cpu, 4);
        let guest_cr3 = hv_breadcrumb(cpu, 5);
        let guest_rflags = hv_breadcrumb(cpu, 6);
        let if_flag = (guest_rflags >> 9) & 1;
        println!(
            "  CPU {:>2}  n={:<6} reason={:<3} rip={:#018x} rsp={:#018x} cr3={:#018x} IF={}",
            cpu, count, exit_reason & 0xFFFF, guest_rip, guest_rsp, guest_cr3, if_flag
        );
    }
    if !any_breadcrumb {
        println!("  (no breadcrumbs recorded)");
    }

    // === KeBugCheckEx Sentinel Address ===
    let kbchk_addr = hv_cmd(CMD_GET_CTL, 50);
    let kbchk_sentinel = hv_cmd(CMD_GET_CTL, 51);
    let kbchk_hits_ram = hv_cmd(CMD_GET_CTL, 52);
    println!("\n=== KeBugCheckEx Sentinel (RAM) ===");
    if kbchk_addr == 0 {
        println!("  [!] Sentinel NOT resolved — init_kebugcheckex_sentinel failed?");
    } else {
        println!("  ADDR:              {:#018x}", kbchk_addr);
        println!("  First 8 bytes:     {:#018x}", kbchk_sentinel);
        println!("  HITS (RAM):        {}", kbchk_hits_ram);
    }

    // === CMOS Freeze Data ===
    println!("\n=== CMOS Freeze Snapshot ===");
    let cmos0 = hv_cmd(CMD_READ_CMOS_FREEZE, 0);
    let magic = (cmos0 & 0xFF) as u8;
    if magic == 0xDE {
        let cpu1 = ((cmos0 >> 8) & 0xFF) as u8;
        let stuck_count = ((cmos0 >> 16) & 0xFFFF) as u16;
        let rip1 = hv_cmd(CMD_READ_CMOS_FREEZE, 1);

        println!("  [+] CMOS DATA FOUND!");
        println!("  Last-write CPU:   #{}", cpu1);
        println!("  RIP:              {:#018x}", rip1);
        println!("  Stuck count:      {} (~{:.1}s in same 128B block)", stuck_count, stuck_count as f64 * 0.075);
        // Clear after reading
        let _ = hv_cmd(CMD_READ_CMOS_FREEZE, 4);
    } else {
        println!("  (no freeze data in CMOS)");
    }

    // CR8 bugcheck diagnostic (standard CMOS 0x72-0x75)
    let cr8_diag = hv_cmd(CMD_READ_CMOS_FREEZE, 5);
    let cr8_marker = (cr8_diag & 0xFF) as u8;
    let cr8_val = ((cr8_diag >> 8) & 0xFF) as u8;
    let cr8_leaf_lo = ((cr8_diag >> 16) & 0xFF) as u8;
    let cr8_leaf_hi = ((cr8_diag >> 24) & 0xFF) as u8;
    if cr8_marker == 0xBC {
        let leaf = (cr8_leaf_hi as u32) << 8 | cr8_leaf_lo as u32;
        println!("\n=== CR8 Bugcheck Diagnostic ===");
        println!("  [+] CR8 HIGH detected during freeze!");
        println!("  CR8 value:        {}", cr8_val);
        println!("  CPUID leaf:       {:#06x}", leaf);
        if cr8_val >= 15 { println!("  Interpretation:   HIGH_LEVEL — KeBugCheckEx in progress"); }
        else if cr8_val >= 14 { println!("  Interpretation:   IPI_LEVEL"); }
        else { println!("  Interpretation:   IRQL >= CLOCK_LEVEL ({})", cr8_val); }
    } else {
        println!("\n=== CR8 Bugcheck Diagnostic ===");
        println!("  (no CR8 high detected, marker=0x{:02x})", cr8_marker);
    }

    // === Step 1-4 CMOS Persistence (2026-07-09) ===
    // Extended CMOS 0x10-0x19 mirrors the freeze-critical RAM state so a
    // hard reboot no longer wipes "who died first" and "what bugcheck code".
    let step4 = hv_cmd(CMD_READ_CMOS_FREEZE, 6);
    let step4_magic = (step4 & 0xFF) as u8;
    println!("\n=== Step 1-4 CMOS (KEBUGCHECKEX / first-fault / total) ===");
    if step4_magic == 0xAB {
        let hits = ((step4 >> 8) & 0xFF) as u8;
        let vec = ((step4 >> 16) & 0xFF) as u8;
        let cpu = ((step4 >> 24) & 0xFF) as u8;
        let total_lo = ((step4 >> 32) & 0xFF) as u16;
        let total_hi = ((step4 >> 40) & 0xFF) as u16;
        let total = total_lo | (total_hi << 8);
        let arg0 = hv_cmd(CMD_READ_CMOS_FREEZE, 7) as u32;

        println!("  [+] Step 1-4 CMOS DATA FOUND!");
        println!("  KEBUGCHECKEX_HITS:     {}", hits);
        if hits > 0 {
            println!("  KEBUGCHECKEX_HIT_ARG0: {:#010x}", arg0);
            match arg0 {
                0x139 => println!("    → KERNEL_SECURITY_CHECK_FAILURE (stack cookie / integrity)"),
                0x109 => println!("    → CRITICAL_STRUCTURE_CORRUPTION (PatchGuard)"),
                0x18b => println!("    → SECURE_KERNEL_ERROR"),
                _ if arg0 != 0 => println!("    → bugcheck code {:#x}, look up in Windows docs", arg0),
                _ => {}
            }
        }
        let vec_name = match vec {
            0 => "(none)",
            2 => "#NMI",
            8 => "#DF (double-fault, cascade)",
            13 => "#GP",
            14 => "#PF",
            18 => "#MC",
            _ => "unknown",
        };
        println!("  HOST_FIRST_FAULT_VECTOR: {} ({})", vec, vec_name);
        if vec != 0 {
            println!("  HOST_FIRST_FAULT_CPU:    #{}", cpu);
        }
        println!("  HOST_FAULT_TOTAL:        {}", total);
    } else {
        println!("  (no Step 1-4 CMOS data, magic=0x{:02x})", step4_magic);
    }

    if !checks_ok {
        std::process::exit(1);
    }
}
