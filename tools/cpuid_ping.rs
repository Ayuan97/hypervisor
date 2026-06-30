use std::arch::asm;

const CPUID_LEAF: u64 = 0x7A3F_E1D9;
const EXPECTED_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;

fn hv_cmd(cmd: u64, arg1: u64) -> u64 {
    let result: u64;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("rax") CPUID_LEAF => result,
            inlateout("rcx") cmd => _,
            inlateout("rdx") arg1 => _,
        );
    }
    result
}

fn main() {
    println!("[*] CPUID Hypervisor Ping (leaf 0x{:X})", CPUID_LEAF);

    let r = hv_cmd(0x01, 0);
    if r != EXPECTED_MAGIC {
        println!("[-] no HV. got 0x{:X}", r);
        return;
    }
    println!("[+] HV alive! magic=0x{:X}", r);

    let cr3 = hv_cmd(0x13, 0);
    println!("[+] guest CR3=0x{:X}", cr3);

    println!("\n=== VMCS Controls ===");
    let names = ["Pin-based", "Primary", "Secondary", "VM-exit", "VM-entry"];
    for (i, name) in names.iter().enumerate() {
        let v = hv_cmd(0x15, i as u64);
        println!("  {:<12} = {:#010x}", name, v);
        if i == 0 {
            println!("    bit0 ExtIntExit={} bit3 NmiExit={} bit5 VirtNmi={} bit6 Preempt={}",
                v & 1, (v >> 3) & 1, (v >> 5) & 1, (v >> 6) & 1);
        }
    }

    println!("\n=== Exit Counters ===");
    let counter_names = [
        "Total", "CPUID", "ExtInt", "Exception", "EPT Viol",
        "EPT Misconfig", "CR Access", "XSETBV", "Other", "MSR",
        "Host #GP", "Host NMI",
    ];
    for (i, name) in counter_names.iter().enumerate() {
        let v = hv_cmd(0x14, i as u64);
        if v > 0 || i == 0 {
            println!("  {:<14} = {}", name, v);
        }
    }

    let last = hv_cmd(0x15, 6);
    println!("  LastExitReason = {:#x}", last);

    let gp_rip = hv_cmd(0x15, 7);
    if gp_rip != 0 && gp_rip != u64::MAX {
        println!("  GP_FAULT_RIP   = {:#x}", gp_rip);
    }
}
