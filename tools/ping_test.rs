//! Standalone user-mode CPUID ping to verify the hypervisor is active.
//! Build: rustc --edition 2021 -o ping_test.exe ping_test.rs
//! Run:   ping_test.exe

use std::arch::asm;

const CPUID_LEAF: u64 = 0x4000_0000;
const HV_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const HV_STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;
const CMD_PING: u64 = 0x01;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_result_reports_sealed_hv_as_active() {
        assert_eq!(ping_result_message(HV_MAGIC), ("[+] HV alive", 0));
        assert_eq!(
            ping_result_message(HV_STATUS_ACCESS_DENIED),
            ("[+] HV alive (diagnostics sealed)", 0)
        );
        assert_eq!(ping_result_message(0), ("[-] no HV", 1));
    }
}

fn ping_result_message(result: u64) -> (&'static str, i32) {
    if result == HV_MAGIC {
        ("[+] HV alive", 0)
    } else if result == HV_STATUS_ACCESS_DENIED {
        ("[+] HV alive (diagnostics sealed)", 0)
    } else {
        ("[-] no HV", 1)
    }
}

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
            in("r8") 0u64,
            in("r9") 0u64,
            in("r10") HV_MAGIC,
            in("r11") HV_MAGIC,
        );
    }
    result
}

fn main() {
    println!("[*] CPUID Ping Test");

    let result = hv_cmd(CMD_PING, 0);
    let (message, code) = ping_result_message(result);
    if code != 0 {
        println!("{}. got 0x{:X}", message, result);
        std::process::exit(code);
    }

    if result == HV_MAGIC {
        println!("{}. magic=0x{:X}", message, result);
    } else {
        println!("{}", message);
    }
}
