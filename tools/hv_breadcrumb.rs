use std::{
    arch::asm,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CPUID_LEAF: u64 = 0x4000_0000;
const EXPECTED_MAGIC: u64 = 0xA3B7_E291_4F6D_8C15;
const STATUS_ACCESS_DENIED: u64 = u64::MAX - 1;

const CMD_PING: u64 = 0x01;
const CMD_GET_COUNTER: u64 = 0x14;
const CMD_GET_CTL: u64 = 0x15;
const CMD_GET_BREADCRUMB: u64 = 0x19;

const FIELD_COUNT: u64 = 0;
const FIELD_EXIT_REASON: u64 = 1;
const FIELD_BASIC_REASON: u64 = 2;
const FIELD_GUEST_RIP: u64 = 3;
const FIELD_GUEST_RSP: u64 = 4;
const FIELD_GUEST_CR3: u64 = 5;
const FIELD_GUEST_RFLAGS: u64 = 6;
const FIELD_EXIT_QUAL: u64 = 7;
const FIELD_GUEST_RAX: u64 = 8;
const FIELD_GUEST_RCX: u64 = 9;
const FIELD_GUEST_RDX: u64 = 10;
const FIELD_DETAIL: u64 = 11;

const DEFAULT_CPUS: u64 = 256;
const DEFAULT_INTERVAL_MS: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    out: Option<PathBuf>,
    interval_ms: u64,
    duration_seconds: u64,
    once: bool,
    cpus: u64,
    include_idle: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            out: None,
            interval_ms: DEFAULT_INTERVAL_MS,
            duration_seconds: 0,
            once: false,
            cpus: DEFAULT_CPUS,
            include_idle: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_names_cover_common_vmexits() {
        assert_eq!(reason_name(10), "CPUID");
        assert_eq!(reason_name(18), "VMCALL");
        assert_eq!(reason_name(48), "EPTViolation");
        assert_eq!(reason_name(0xFFFF), "Unknown");
    }

    #[test]
    fn parser_accepts_core_flags() {
        let args = [
            "hv_breadcrumb.exe",
            "--once",
            "--out",
            "x.csv",
            "--interval-ms",
            "250",
            "--duration-seconds",
            "5",
            "--cpus",
            "24",
            "--include-idle",
        ];
        let cfg = parse_config_from(args.iter().copied()).unwrap();
        assert!(cfg.once);
        assert_eq!(cfg.out, Some(PathBuf::from("x.csv")));
        assert_eq!(cfg.interval_ms, 250);
        assert_eq!(cfg.duration_seconds, 5);
        assert_eq!(cfg.cpus, 24);
        assert!(cfg.include_idle);
    }

    #[test]
    fn csv_escape_quotes_values_when_needed() {
        assert_eq!(csv("plain"), "plain");
        assert_eq!(csv("a,b"), "\"a,b\"");
        assert_eq!(csv("a\"b"), "\"a\"\"b\"");
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

fn access_denied(value: u64) -> bool {
    value == STATUS_ACCESS_DENIED
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn read_counter(id: u64) -> u64 {
    hv(CMD_GET_COUNTER, id, 0, 0)
}

fn read_ctl(id: u64) -> u64 {
    hv(CMD_GET_CTL, id, 0, 0)
}

fn read_breadcrumb(cpu: u64, field: u64) -> u64 {
    hv(CMD_GET_BREADCRUMB, cpu, field, 0)
}

fn reason_name(reason: u64) -> &'static str {
    match reason {
        0 => "ExceptionOrNmi",
        1 => "ExternalInterrupt",
        2 => "TripleFault",
        7 => "InterruptWindow",
        8 => "NmiWindow",
        10 => "CPUID",
        12 => "HLT",
        13 => "INVD",
        16 => "RDTSC",
        18 => "VMCALL",
        23 => "VMREAD",
        24 => "VMRESUME",
        25 => "VMWRITE",
        26 => "VMXOFF",
        27 => "VMXON",
        28 => "ControlRegAccess",
        31 => "RDMSR",
        32 => "WRMSR",
        37 => "MonitorTrapFlag",
        48 => "EPTViolation",
        49 => "EPTMisconfig",
        51 => "RDTSCP",
        54 => "WBINVD",
        55 => "XSETBV",
        60 => "ENCLS",
        70 => "ENCLV",
        74 => "BusLock",
        75 => "InstructionTimeout",
        _ => "Unknown",
    }
}

fn csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn parse_u64_arg(name: &str, value: Option<&str>) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("missing value for {}", name))?;
    value
        .parse::<u64>()
        .map_err(|_| format!("invalid value for {}: {}", name, value))
}

fn parse_config_from<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut iter = args.into_iter();
    let _program = iter.next();

    while let Some(arg) = iter.next() {
        match arg {
            "--out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                cfg.out = Some(PathBuf::from(value));
            }
            "--interval-ms" => cfg.interval_ms = parse_u64_arg(arg, iter.next())?,
            "--duration-seconds" => cfg.duration_seconds = parse_u64_arg(arg, iter.next())?,
            "--cpus" => cfg.cpus = parse_u64_arg(arg, iter.next())?,
            "--once" => cfg.once = true,
            "--include-idle" => cfg.include_idle = true,
            "--help" | "-h" => return Err(help_text()),
            _ => return Err(format!("unknown argument: {}\n{}", arg, help_text())),
        }
    }

    if cfg.interval_ms == 0 {
        return Err("--interval-ms must be greater than 0".to_string());
    }
    if cfg.cpus == 0 || cfg.cpus > DEFAULT_CPUS {
        return Err(format!("--cpus must be in 1..={}", DEFAULT_CPUS));
    }

    Ok(cfg)
}

fn parse_config() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().collect();
    parse_config_from(args.iter().map(String::as_str))
}

fn help_text() -> String {
    "usage: hv_breadcrumb.exe [--out path] [--interval-ms n] [--duration-seconds n] [--cpus n] [--once] [--include-idle]".to_string()
}

fn open_log(path: &PathBuf) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)
}

fn header() -> &'static str {
    "time_ms,tick,cpu,count,exit_reason,basic_reason,reason,guest_rip,guest_rsp,guest_cr3,guest_rflags,exit_qual,guest_rax,guest_rcx,guest_rdx,detail,total,cpuid,ext_int,exception,ept_violation,ept_misconfig,cr_access,msr,xsetbv,other,host_gp,host_nmi,boot_stage,idt_patch_calls,idt_patch_ok_calls,idt_cpu,idt_mask,idt_base,idt_limit,vmcs_idt_base,idt_nmi_target,idt_gp_target,idt_nmi_expected,idt_gp_expected,idt_mc_target,idt_mc_expected,host_mc,mc_fault_rip,idt_pf_target,idt_pf_expected,host_pf,pf_fault_rip,pf_fault_cr2\r\n"
}

fn format_row(
    time_ms: u128,
    tick: u64,
    cpu: &str,
    count: u64,
    exit_reason: u64,
    basic_reason: u64,
    guest_rip: u64,
    guest_rsp: u64,
    guest_cr3: u64,
    guest_rflags: u64,
    exit_qual: u64,
    guest_rax: u64,
    guest_rcx: u64,
    guest_rdx: u64,
    detail: u64,
    counters: &[u64; 12],
    boot_stage: u64,
    idt_status: &[u64; 20],
) -> String {
    format!(
        "{},{},{},{},{:#x},{:#x},{},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{},{:#x},{:#x},{:#x},{},{:#x},{:#x}\r\n",
        time_ms,
        tick,
        csv(cpu),
        count,
        exit_reason,
        basic_reason,
        csv(reason_name(basic_reason)),
        guest_rip,
        guest_rsp,
        guest_cr3,
        guest_rflags,
        exit_qual,
        guest_rax,
        guest_rcx,
        guest_rdx,
        detail,
        counters[0],
        counters[1],
        counters[2],
        counters[3],
        counters[4],
        counters[5],
        counters[6],
        counters[9],
        counters[7],
        counters[8],
        counters[10],
        counters[11],
        boot_stage,
        idt_status[0],
        idt_status[1],
        idt_status[2],
        idt_status[3],
        idt_status[4],
        idt_status[5],
        idt_status[6],
        idt_status[7],
        idt_status[8],
        idt_status[9],
        idt_status[10],
        idt_status[11],
        idt_status[12],
        idt_status[13],
        idt_status[14],
        idt_status[15],
        idt_status[16],
        idt_status[17],
        idt_status[18],
        idt_status[19],
    )
}

fn sample_tick(tick: u64, cfg: &Config) -> Result<String, String> {
    let ping = hv(CMD_PING, 0, 0, 0);
    if access_denied(ping) {
        return Err("diagnostics sealed; restart with HV_NO_SEAL=1 for breadcrumbs".to_string());
    }
    if ping != EXPECTED_MAGIC {
        return Err(format!("HV inactive or unexpected ping: 0x{:x}", ping));
    }

    let mut counters = [0u64; 12];
    for (id, value) in counters.iter_mut().enumerate() {
        *value = read_counter(id as u64);
    }
    let boot_stage = read_ctl(9);
    let mut idt_status = [0u64; 20];
    for (idx, value) in idt_status.iter_mut().enumerate() {
        *value = read_ctl(10 + idx as u64);
    }
    let time = now_ms();

    let mut out = String::new();
    out.push_str(&format_row(
        time,
        tick,
        "summary",
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        &counters,
        boot_stage,
        &idt_status,
    ));

    for cpu in 0..cfg.cpus {
        let count = read_breadcrumb(cpu, FIELD_COUNT);
        if access_denied(count) {
            return Err("breadcrumb command denied; diagnostics may be sealed".to_string());
        }
        if count == 0 && !cfg.include_idle {
            continue;
        }

        let exit_reason = read_breadcrumb(cpu, FIELD_EXIT_REASON);
        let basic_reason = read_breadcrumb(cpu, FIELD_BASIC_REASON);
        let guest_rip = read_breadcrumb(cpu, FIELD_GUEST_RIP);
        let guest_rsp = read_breadcrumb(cpu, FIELD_GUEST_RSP);
        let guest_cr3 = read_breadcrumb(cpu, FIELD_GUEST_CR3);
        let guest_rflags = read_breadcrumb(cpu, FIELD_GUEST_RFLAGS);
        let exit_qual = read_breadcrumb(cpu, FIELD_EXIT_QUAL);
        let guest_rax = read_breadcrumb(cpu, FIELD_GUEST_RAX);
        let guest_rcx = read_breadcrumb(cpu, FIELD_GUEST_RCX);
        let guest_rdx = read_breadcrumb(cpu, FIELD_GUEST_RDX);
        let detail = read_breadcrumb(cpu, FIELD_DETAIL);

        out.push_str(&format_row(
            time,
            tick,
            &cpu.to_string(),
            count,
            exit_reason,
            basic_reason,
            guest_rip,
            guest_rsp,
            guest_cr3,
            guest_rflags,
            exit_qual,
            guest_rax,
            guest_rcx,
            guest_rdx,
            detail,
            &counters,
            boot_stage,
            &idt_status,
        ));
    }

    Ok(out)
}

fn run(cfg: Config) -> Result<(), String> {
    let mut file = if let Some(path) = &cfg.out {
        let mut file =
            open_log(path).map_err(|e| format!("open {} failed: {}", path.display(), e))?;
        if file.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            file.write_all(header().as_bytes())
                .map_err(|e| format!("write header failed: {}", e))?;
            file.sync_all()
                .map_err(|e| format!("sync header failed: {}", e))?;
        }
        Some(file)
    } else {
        print!("{}", header());
        None
    };

    let start = Instant::now();
    let mut tick = 0u64;
    loop {
        let rows = sample_tick(tick, &cfg)?;
        print!("{}", rows);
        io::stdout()
            .flush()
            .map_err(|e| format!("stdout flush failed: {}", e))?;

        if let Some(file) = file.as_mut() {
            file.write_all(rows.as_bytes())
                .map_err(|e| format!("write rows failed: {}", e))?;
            file.flush().map_err(|e| format!("flush failed: {}", e))?;
            file.sync_all().map_err(|e| format!("sync failed: {}", e))?;
        }

        tick = tick.wrapping_add(1);
        if cfg.once {
            break;
        }
        if cfg.duration_seconds > 0 && start.elapsed().as_secs() >= cfg.duration_seconds {
            break;
        }
        thread::sleep(Duration::from_millis(cfg.interval_ms));
    }
    Ok(())
}

fn main() {
    match parse_config().and_then(run) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(1);
        }
    }
}
