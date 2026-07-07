use std::arch::asm;
use std::io::Write;

const CPUID_LEAF: u64 = 0x4000_0000;
const EXPECTED_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const CMD_GET_COUNTER: u64 = 0x14;
const CMD_GET_CPU_DIAG: u64 = 0x28;

fn cpuid_cmd(leaf: u64, cmd: u64, arg1: u64, token: u64) -> u64 {
    cpuid_cmd2(leaf, cmd, arg1, 0, token)
}

fn hv_cmd(cmd: u64, arg1: u64) -> u64 {
    cpuid_cmd(CPUID_LEAF, cmd, arg1, EXPECTED_MAGIC)
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

fn get_cpu_diag(cpu: u64, field: u64) -> u64 {
    cpuid_cmd2(CPUID_LEAF, CMD_GET_CPU_DIAG, cpu, field, EXPECTED_MAGIC)
}

fn main() {
    println!("=== Freeze Watchdog ===");
    println!("Polling HV state every 500ms. Last output before freeze = root cause.");
    println!("handler IDs: 1=CPUID 2=MSR 3=INVD 5=CR 7=EPT_VIOL 8=EPT_MISCONF");
    println!("             9=VMCALL 10=RDTSC 11=RDTSCP 12=XSETBV 13=MTF");
    println!("             14=INVEPT 15=INVVPID 16=WBINVD 17=EXCPT 18=XSETBV 19=TIMER 99=OTHER");
    println!();

    let num_cpus = 24u64;
    let mut prev_heartbeats = vec![0u64; num_cpus as usize];
    let mut prev_cpuid = 0u64;
    let mut iteration = 0u64;

    // Initial heartbeat snapshot
    for cpu in 0..num_cpus {
        prev_heartbeats[cpu as usize] = get_cpu_diag(cpu, 0);
    }
    prev_cpuid = hv_cmd(CMD_GET_COUNTER, 1);

    loop {
        iteration += 1;
        std::thread::sleep(std::time::Duration::from_millis(500));

        let exit_cpuid = hv_cmd(CMD_GET_COUNTER, 1);
        let exit_preempt = hv_cmd(CMD_GET_COUNTER, 24);

        // Check which CPUs are stuck (heartbeat not advancing)
        let mut stuck_cpus = Vec::new();
        for cpu in 0..num_cpus {
            let hb = get_cpu_diag(cpu, 0);
            if hb == prev_heartbeats[cpu as usize] && hb > 0 {
                let phase = get_cpu_diag(cpu, 1);
                let leaf = get_cpu_diag(cpu, 2);
                stuck_cpus.push((cpu, phase, leaf));
            }
            prev_heartbeats[cpu as usize] = hb;
        }

        let cpuid_delta = exit_cpuid - prev_cpuid;
        prev_cpuid = exit_cpuid;

        if !stuck_cpus.is_empty() || iteration % 20 == 0 {
            print!("[{:>4}] cpuid_d={:<4} timer={} ", iteration, cpuid_delta, exit_preempt);
            if stuck_cpus.is_empty() {
                print!("| all CPUs alive");
            } else {
                print!("| STUCK({}):", stuck_cpus.len());
                for (cpu, phase, leaf) in &stuck_cpus {
                    print!(" cpu{}=ph{:#x}/leaf{:#x}", cpu, phase, leaf);
                }
            }
            println!();
            std::io::stdout().flush().unwrap();
        }
    }
}
