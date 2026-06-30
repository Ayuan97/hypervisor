//! Standalone test: VMCALL ping to verify hypervisor is active.
//! Build: rustc --edition 2021 -o ping_test.exe ping_test.rs
//! Run:   ping_test.exe

#![feature(asm_const)]

const VMCALL_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const CMD_PING: u64 = 0x01;
const CMD_GET_GUEST_CR3: u64 = 0x13;

unsafe fn vmcall(rax: u64, rcx: u64, rdx: u64, r8: u64, r9: u64) -> u64 {
    let result: u64;
    core::arch::asm!(
        "vmcall",
        inlateout("rax") rax => result,
        in("rcx") rcx,
        in("rdx") rdx,
        in("r8") r8,
        in("r9") r9,
        options(nostack),
    );
    result
}

fn main() {
    println!("[*] VMCALL Ping Test");
    println!("[*] Sending VMCALL with magic 0x{:X}...", VMCALL_MAGIC);

    let result = unsafe { vmcall(VMCALL_MAGIC, CMD_PING, 0, 0, 0) };

    if result == VMCALL_MAGIC {
        println!("[+] Hypervisor responded! Magic = 0x{:X}", result);

        let cr3 = unsafe { vmcall(VMCALL_MAGIC, CMD_GET_GUEST_CR3, 0, 0, 0) };
        println!("[+] Guest CR3 = 0x{:X}", cr3);

        println!("[+] All checks passed - hypervisor is active.");
    } else {
        println!("[-] No response. Result = 0x{:X}", result);
        println!("[-] Hypervisor is NOT running.");
    }
}
