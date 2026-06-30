use std::arch::asm;
use std::io::Write;

const CPUID_LEAF: u64 = 0x7A3F_E1D9;
const EXPECTED_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const HV_STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;

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
        );
    }
    result
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

    println!("=== HV User-Mode Safety Diagnostic ===\n");

    step(1, 4, "CPUID ping");
    let r = hv(0x01, 0, 0, 0);
    if r != EXPECTED_MAGIC {
        println!("FAIL (0x{:X})", r);
        println!("\nHV not loaded. Run start_hv.bat first.");
        pause();
        return;
    }
    println!("OK");

    step(2, 4, "get guest CR3");
    let cr3 = hv(0x13, 0, 0, 0);
    if cr3 == 0 {
        println!("FAIL");
        pause();
        return;
    }
    println!("OK (0x{:X})", cr3);

    step(3, 4, "read IDENTITY_CR3 (ctl index 5)");
    let id_cr3 = hv(0x15, 5, 0, 0);
    println!("0x{:X}", id_cr3);
    if id_cr3 == 0 || id_cr3 == u64::MAX {
        println!("\n[!] IDENTITY_CR3 invalid. Identity page tables not initialized.");
        pause();
        return;
    }

    step(4, 4, "read_phys(PA=0, 8 bytes) denied from user mode");
    let v = hv(0x10, 0, 8, 0);
    if v == HV_STATUS_ACCESS_DENIED {
        println!("OK");
    } else {
        println!("FAIL (expected access denied, got 0x{:X})", v);
        pause();
        return;
    }

    println!("\n=== User-mode safety checks passed ===");
    println!("\nPhysical read/write/translate commands are restricted to CPL0 callers.");
    println!("Tip: run `phys_test.exe monitor` to watch exit counters while starting the game.");
    pause();
}

fn monitor() {
    println!("=== VM Exit Monitor ===");
    println!("Polling exit counters every 500ms. Start the game now.");
    println!("If the system freezes, the last line printed is the clue.\n");

    let r = hv(0x01, 0, 0, 0);
    if r != EXPECTED_MAGIC {
        println!("HV not loaded.");
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
            18 => "VMCALL",
            28 => "ControlRegAccess",
            30 => "IOInstruction",
            31 => "RDMSR",
            32 => "WRMSR",
            33 => "EntryFail_Guest",
            34 => "EntryFail_MSR",
            37 => "MonitorTrapFlag",
            43 => "TPR_Below",
            48 => "EPTViolation",
            49 => "EPTMisconfig",
            50 => "INVEPT",
            53 => "INVVPID",
            55 => "XSETBV",
            58 => "RDTSCP",
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

        let delta = total.wrapping_sub(prev_total);
        let line = format!(
            "[{:>4}] T={:<8} +{:<6} CPUID={} ExtInt={} Exc={} EPT_V={} CR={} MSR={} XSETBV={} Other={} last={}({})",
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
            last_reason,
            reason_name(last_reason)
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
