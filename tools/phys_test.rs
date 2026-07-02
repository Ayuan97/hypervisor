use std::arch::asm;
use std::io::Write;

const CPUID_LEAF: u64 = 0x4000_0000;
const EXPECTED_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const HV_STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;
const HV_STATUS_PENDING: u64 = u64::MAX - 3;
const CMD_GET_GUEST_CR3: u64 = 0x13;
const CMD_ARM_CLIENT_READS: u64 = 0x17;
const CMD_READ_PHYS_RESULT: u64 = 0x18;
const CMD_GET_CLIENT_READ_STATE: u64 = 0x1A;
const CMD_READ_VIRT: u64 = 0x1B;
const CMD_RELEASE_READ_RESULT: u64 = 0x1E;
const CLIENT_READ_ARM_TOKEN: u64 = 0xC17E_A2D5_90B4_6F31;
const READ_POLL_LIMIT: usize = 2_000_000;

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
    fn ping_response_distinguishes_loaded_from_missing_hv() {
        assert!(ping_response_indicates_loaded(EXPECTED_MAGIC));
        assert!(ping_response_indicates_loaded(HV_STATUS_ACCESS_DENIED));
        assert!(!ping_response_indicates_loaded(0));
    }

    #[test]
    fn read_phys_denial_marks_game_safe_mode() {
        assert!(read_result_indicates_game_safe(HV_STATUS_ACCESS_DENIED));
        assert!(read_result_indicates_game_safe(HV_STATUS_PENDING));
        assert!(!read_result_indicates_game_safe(0));
        assert!(!read_result_indicates_game_safe(EXPECTED_MAGIC));
    }

    #[test]
    fn read_result_matches_expected_mode() {
        assert!(read_result_matches_mode(HV_STATUS_ACCESS_DENIED, false));
        assert!(!read_result_matches_mode(0, false));
        assert!(read_result_matches_mode(0, true));
        assert!(!read_result_matches_mode(HV_STATUS_ACCESS_DENIED, true));
    }

    #[test]
    fn arm_success_requires_zero_status() {
        assert!(arm_status_indicates_success(0));
        assert!(!arm_status_indicates_success(HV_STATUS_ACCESS_DENIED));
        assert!(!arm_status_indicates_success(u64::MAX));
    }

    #[test]
    fn arm_request_uses_client_read_token() {
        assert_eq!(client_read_arm_token(), 0xC17E_A2D5_90B4_6F31);
        assert_ne!(client_read_arm_token(), 0);
    }
}

fn hv(cmd: u64, p1: u64, p2: u64, p3: u64) -> u64 {
    let result: u64;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("rax") CPUID_LEAF => result,
            inlateout("rcx") cmd => _,
            inlateout("rdx") p1 => _,
            in("r8") p2,
            in("r9") p3,
            in("r10") EXPECTED_MAGIC,
            in("r11") EXPECTED_MAGIC,
        );
    }
    result
}

fn diagnostics_access_denied(value: u64) -> bool {
    value == HV_STATUS_ACCESS_DENIED
}

fn ping_response_indicates_loaded(value: u64) -> bool {
    value == EXPECTED_MAGIC || diagnostics_access_denied(value)
}

fn read_result_indicates_game_safe(value: u64) -> bool {
    diagnostics_access_denied(value) || value == HV_STATUS_PENDING
}

fn read_result_matches_mode(value: u64, expect_client_reads: bool) -> bool {
    if expect_client_reads {
        !diagnostics_access_denied(value)
    } else {
        read_result_indicates_game_safe(value)
    }
}

fn arm_status_indicates_success(value: u64) -> bool {
    value == 0
}

fn client_read_arm_token() -> u64 {
    CLIENT_READ_ARM_TOKEN
}

fn read_phys(pa: u64, size: u64) -> Option<u64> {
    let seq = hv(0x10, pa, size, 0);
    if seq == 0 || read_result_indicates_game_safe(seq) {
        return None;
    }

    let started = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(15);
    for i in 0..READ_POLL_LIMIT {
        if started.elapsed() >= timeout {
            return None;
        }
        let result = hv(CMD_READ_PHYS_RESULT, seq, 0, 0);
        if result == HV_STATUS_PENDING {
            if i % 1024 == 0 {
                std::thread::sleep(std::time::Duration::from_micros(200));
            } else if i % 64 == 0 {
                std::thread::yield_now();
            }
            continue;
        }
        if read_result_indicates_game_safe(result) {
            return None;
        }
        return Some(result);
    }
    None
}

fn read_virt(cr3: u64, va: u64, size: u64) -> Option<u64> {
    let seq = hv(CMD_READ_VIRT, cr3, va, size);
    if seq == 0 || read_result_indicates_game_safe(seq) {
        return None;
    }

    let started = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(15);
    for i in 0..READ_POLL_LIMIT {
        if started.elapsed() >= timeout {
            return None;
        }
        let result = hv(CMD_READ_PHYS_RESULT, seq, 0, 0);
        if result == HV_STATUS_PENDING {
            if i % 1024 == 0 {
                std::thread::sleep(std::time::Duration::from_micros(200));
            } else if i % 64 == 0 {
                std::thread::yield_now();
            }
            continue;
        }
        if read_result_indicates_game_safe(result) {
            return None;
        }
        return Some(result);
    }
    None
}

fn client_read_state_line() -> String {
    let names = [
        "enabled",
        "worker",
        "request_seq",
        "done_seq",
        "result_status",
        "request_pa",
        "request_size",
        "shutdown",
        "request_kind",
        "request_cr3",
        "request_va",
        "slot_state",
        "result_size",
    ];
    let mut parts = Vec::new();
    for (i, name) in names.iter().enumerate() {
        parts.push(format!(
            "{}=0x{:x}",
            name,
            hv(CMD_GET_CLIENT_READ_STATE, i as u64, 0, 0)
        ));
    }
    parts.join(" ")
}

fn step(n: u32, total: u32, desc: &str) {
    print!("[{}/{}] {}... ", n, total, desc);
    std::io::stdout().flush().unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "monitor" {
        monitor();
        return;
    }
    if args.len() > 1 && args[1] == "release-current" {
        let seq = hv(CMD_GET_CLIENT_READ_STATE, 2, 0, 0);
        let result = hv(CMD_RELEASE_READ_RESULT, seq, 0, 0);
        println!("release-current seq=0x{:x} result=0x{:x}", seq, result);
        println!("client_read_state: {}", client_read_state_line());
        return;
    }
    let arm_client_reads = args.iter().any(|arg| arg == "--arm-client");
    let expect_client_reads = arm_client_reads || args.iter().any(|arg| arg == "--expect-client");

    println!("=== HV Game-Safe Client Diagnostic ===\n");

    let total_steps = if expect_client_reads {
        if arm_client_reads {
            4
        } else {
            3
        }
    } else {
        2
    };

    if arm_client_reads {
        step(1, total_steps, "arm client reads");
        let armed = hv(CMD_ARM_CLIENT_READS, client_read_arm_token(), 0, 0);
        if !arm_status_indicates_success(armed) {
            println!("FAIL (0x{:X})", armed);
            pause();
            return;
        }
        println!("OK");
    }

    let ping_step = if arm_client_reads { 2 } else { 1 };
    step(ping_step, total_steps, "CPUID ping");
    let r = hv(0x01, 0, 0, 0);
    if diagnostics_access_denied(r) {
        println!("SEALED");
        println!("\nHV is loaded, but diagnostics are sealed.");
        println!("Run this before sealing, or start with HV_NO_SEAL=1 for diagnostics.");
        pause();
        return;
    }
    if !ping_response_indicates_loaded(r) {
        println!("FAIL (0x{:X})", r);
        println!("\nHV not loaded. Run start_hv.bat first.");
        pause();
        return;
    }
    println!("OK");

    let read_pa = if expect_client_reads {
        let cr3 = hv(CMD_GET_GUEST_CR3, 0, 0, 0);
        if cr3 == 0 || diagnostics_access_denied(cr3) {
            println!("\nFAIL: get guest CR3 returned 0x{:X}", cr3);
            println!("client_read_state: {}", client_read_state_line());
            pause();
            return;
        }
        cr3 & !0xfff
    } else {
        0
    };

    if expect_client_reads {
        step(
            total_steps - 1,
            total_steps,
            "authenticated read_phys(current CR3 page, 8 bytes)",
        );
    } else {
        step(
            total_steps,
            total_steps,
            "read_phys(PA=0, 8 bytes) denied from user mode",
        );
    }
    let v = if expect_client_reads {
        read_phys(read_pa, 8).unwrap_or(HV_STATUS_ACCESS_DENIED)
    } else {
        hv(0x10, 0, 8, 0)
    };
    if !read_result_matches_mode(v, expect_client_reads) {
        if expect_client_reads {
            println!("FAIL (access denied)");
            println!("client_read_state: {}", client_read_state_line());
        } else {
            println!("FAIL (expected access denied, got 0x{:X})", v);
        }
        pause();
        return;
    }
    if expect_client_reads {
        println!("OK (0x{:X})", v);
    } else {
        println!("OK");
    }

    if expect_client_reads {
        let canary = 0x1122_3344_5566_7788u64;
        step(
            total_steps,
            total_steps,
            "authenticated read_virt(current process canary, 8 bytes)",
        );
        let canary_va = (&canary as *const u64) as u64;
        let got = read_virt(hv(CMD_GET_GUEST_CR3, 0, 0, 0), canary_va, 8);
        if got != Some(canary) {
            println!("FAIL (got {:?}, expected 0x{:X})", got, canary);
            println!("client_read_state: {}", client_read_state_line());
            pause();
            return;
        }
        println!("OK (0x{:X})", got.unwrap());
    }

    if expect_client_reads {
        println!("\n=== User client checks passed ===");
        println!(
            "\nAuthenticated physical and virtual read commands are available to the user client."
        );
        println!("Physical write remains disabled in the hypervisor.");
    } else {
        println!("\n=== User-mode safety checks passed ===");
        println!("\nPhysical read/write/translate commands are restricted to CPL0 callers.");
        println!("Physical write remains disabled in the hypervisor.");
    }
    println!("Tip: run `phys_test.exe monitor` to watch exit counters while starting the game.");
    pause();
}

fn monitor() {
    println!("=== VM Exit Monitor ===");
    println!("Polling exit counters every 500ms. Start the game now.");
    println!("If the system freezes, the last line printed is the clue.\n");

    let r = hv(0x01, 0, 0, 0);
    if diagnostics_access_denied(r) {
        println!("Diagnostics are sealed.");
        println!("Restart and run scripts\\start_hv.bat with HV_NO_SEAL=1 before using monitor.");
        pause();
        return;
    }
    if !ping_response_indicates_loaded(r) {
        println!("HV not loaded.");
        pause();
        return;
    }

    if diagnostics_access_denied(hv(0x14, 0, 0, 0)) {
        println!("Diagnostics are sealed.");
        println!("Restart and run scripts\\start_hv.bat with HV_NO_SEAL=1 before using monitor.");
        pause();
        return;
    }

    let reason_name = |r: u64| -> &'static str {
        match r {
            0 => "ExceptionOrNmi",
            1 => "ExternalInterrupt",
            2 => "TripleFault",
            7 => "InterruptWindow",
            10 => "CPUID",
            12 => "HLT",
            13 => "INVD",
            15 => "RDPMC",
            16 => "RDTSC",
            18 => "VMCALL",
            19 => "VMCLEAR",
            20 => "VMLAUNCH",
            21 => "VMPTRLD",
            22 => "VMPTRST",
            23 => "VMREAD",
            24 => "VMRESUME",
            25 => "VMWRITE",
            26 => "VMXOFF",
            27 => "VMXON",
            28 => "ControlRegAccess",
            30 => "IOInstruction",
            31 => "RDMSR",
            32 => "WRMSR",
            33 => "EntryFail_Guest",
            34 => "EntryFail_MSR",
            36 => "MWAIT",
            37 => "MonitorTrapFlag",
            40 => "PAUSE",
            43 => "TPR_Below",
            48 => "EPTViolation",
            49 => "EPTMisconfig",
            50 => "INVEPT",
            51 => "RDTSCP",
            53 => "INVVPID",
            54 => "WBINVD",
            55 => "XSETBV",
            57 => "RDRAND",
            58 => "INVPCID",
            59 => "VMFUNC",
            60 => "ENCLS",
            61 => "RDSEED",
            62 => "PMLFull",
            63 => "XSAVES",
            64 => "XRSTORS",
            65 => "PCONFIG",
            67 => "UMWAIT",
            68 => "TPAUSE",
            69 => "LOADIWKEY",
            70 => "ENCLV",
            74 => "BusLock",
            75 => "InstructionTimeout",
            _ => "Unknown",
        }
    };

    let mut prev_total: u64 = 0;
    let mut tick: u64 = 0;
    let log = std::fs::File::create("monitor_log.txt").ok();

    loop {
        let total = hv(0x14, 0, 0, 0);
        let cpuid = hv(0x14, 1, 0, 0);
        let ext_int = hv(0x14, 2, 0, 0);
        let exc = hv(0x14, 3, 0, 0);
        let ept_v = hv(0x14, 4, 0, 0);
        let cr = hv(0x14, 6, 0, 0);
        let xsetbv = hv(0x14, 7, 0, 0);
        let other = hv(0x14, 8, 0, 0);
        let msr = hv(0x14, 9, 0, 0);
        let last_reason = hv(0x15, 6, 0, 0);
        let tsc_offset = hv(0x15, 8, 0, 0);
        let basic_reason = last_reason & 0xffff;

        let delta = total.wrapping_sub(prev_total);
        let line = format!(
            "[{:>4}] T={:<8} +{:<6} CPUID={} ExtInt={} Exc={} EPT_V={} CR={} MSR={} XSETBV={} Other={} TSC_OFF={:#x} last={}({})",
            tick,
            total,
            delta,
            cpuid,
            ext_int,
            exc,
            ept_v,
            cr,
            msr,
            xsetbv,
            other,
            tsc_offset,
            last_reason,
            reason_name(basic_reason)
        );
        println!("{}", line);
        std::io::stdout().flush().unwrap();

        if let Some(ref f) = log {
            let _ = writeln!(&*f, "{}", line);
            let _ = f.sync_all();
        }

        prev_total = total;
        tick += 1;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn pause() {
    print!("\nPress Enter to exit...");
    std::io::stdout().flush().unwrap();
    let _ = std::io::stdin().read_line(&mut String::new());
}
