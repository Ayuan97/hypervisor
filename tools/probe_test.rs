use std::{
    arch::asm,
    ffi::c_void,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;

static LAST_EXCEPTION: AtomicU32 = AtomicU32::new(0);
static EXCEPTION_HIT: AtomicUsize = AtomicUsize::new(0);
static SKIP_LEN: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut ExceptionRecord,
    exception_address: *mut c_void,
    number_parameters: u32,
    exception_information: [usize; 15],
}

#[repr(C)]
struct ContextPrefix {
    p_home: [u64; 6],
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr: [u64; 6],
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
}

#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut ContextPrefix,
}

#[link(name = "kernel32")]
extern "system" {
    fn AddVectoredExceptionHandler(
        first: u32,
        handler: Option<unsafe extern "system" fn(*mut ExceptionPointers) -> i32>,
    ) -> *mut c_void;
    fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
}

unsafe extern "system" fn veh(info: *mut ExceptionPointers) -> i32 {
    let skip = SKIP_LEN.load(Ordering::SeqCst);
    if skip == 0 || info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_record = (*info).exception_record;
    let context_record = (*info).context_record;
    if exception_record.is_null() || context_record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    LAST_EXCEPTION.store((*exception_record).exception_code, Ordering::SeqCst);
    EXCEPTION_HIT.fetch_add(1, Ordering::SeqCst);
    (*context_record).rip = (*context_record).rip.wrapping_add(skip as u64);
    EXCEPTION_CONTINUE_EXECUTION
}

struct VehGuard(*mut c_void);

impl VehGuard {
    fn install() -> Option<Self> {
        let handle = unsafe { AddVectoredExceptionHandler(1, Some(veh)) };
        (!handle.is_null()).then_some(Self(handle))
    }
}

impl Drop for VehGuard {
    fn drop(&mut self) {
        unsafe {
            RemoveVectoredExceptionHandler(self.0);
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct ProbeResult {
    name: &'static str,
    exception_code: u32,
    hit: bool,
}

fn run_probe(name: &'static str, skip_len: usize, probe: unsafe fn()) -> ProbeResult {
    LAST_EXCEPTION.store(0, Ordering::SeqCst);
    EXCEPTION_HIT.store(0, Ordering::SeqCst);
    SKIP_LEN.store(skip_len, Ordering::SeqCst);

    unsafe { probe() };

    SKIP_LEN.store(0, Ordering::SeqCst);
    ProbeResult {
        name,
        exception_code: LAST_EXCEPTION.load(Ordering::SeqCst),
        hit: EXCEPTION_HIT.load(Ordering::SeqCst) != 0,
    }
}

unsafe fn probe_vmread() {
    asm!(
        "xor rax, rax",
        "vmread rax, rax",
        out("rax") _,
        options(nostack)
    );
}

unsafe fn probe_vmwrite() {
    asm!(
        "xor rax, rax",
        "vmwrite rax, rax",
        out("rax") _,
        options(nostack)
    );
}

unsafe fn probe_vmlaunch() {
    asm!(".byte 0x0f, 0x01, 0xc2", options(nostack));
}

unsafe fn probe_vmresume() {
    asm!(".byte 0x0f, 0x01, 0xc3", options(nostack));
}

unsafe fn probe_vmxoff() {
    asm!(".byte 0x0f, 0x01, 0xc4", options(nostack));
}

unsafe fn probe_vmcall_with_token() {
    asm!(
        "vmcall",
        in("rax") 0xA3B7_E291_4F6D_8C15u64,
        in("rcx") 0x01u64,
        in("rdx") 0u64,
        in("r8") 0u64,
        in("r9") 0u64,
        in("r10") 0xA3B7_E291_4F6D_8C15u64,
        in("r11") 0xA3B7_E291_4F6D_8C15u64,
        options(nostack)
    );
}

unsafe fn probe_xsetbv_same_value() {
    let xcr0 = xgetbv0();
    asm!(
        "xsetbv",
        in("ecx") 0u32,
        in("eax") xcr0 as u32,
        in("edx") (xcr0 >> 32) as u32,
        options(nostack)
    );
}

unsafe fn probe_encls() {
    asm!(".byte 0x0f, 0x01, 0xcf", options(nostack));
}

unsafe fn probe_enclv() {
    asm!(".byte 0x0f, 0x01, 0xc0", options(nostack));
}

unsafe fn probe_invd() {
    asm!("invd", options(nostack));
}

unsafe fn probe_wbinvd() {
    asm!("wbinvd", options(nostack));
}

unsafe fn probe_out_of_range_rdmsr() {
    asm!(
        "rdmsr",
        in("ecx") 0x4000_0000u32,
        lateout("eax") _,
        lateout("edx") _,
        options(nostack)
    );
}

unsafe fn probe_out_of_range_wrmsr() {
    asm!(
        "wrmsr",
        in("ecx") 0x4000_0000u32,
        in("eax") 0u32,
        in("edx") 0u32,
        options(nostack)
    );
}

fn xgetbv0() -> u64 {
    let eax: u32;
    let edx: u32;
    unsafe {
        asm!(
            "xgetbv",
            in("ecx") 0u32,
            out("eax") eax,
            out("edx") edx,
            options(nostack)
        );
    }
    (eax as u64) | ((edx as u64) << 32)
}

fn main() {
    println!("=== User-mode Probe Test ===");
    let only = std::env::args().find_map(|arg| arg.strip_prefix("--only=").map(str::to_owned));

    let Some(_veh) = VehGuard::install() else {
        println!("[-] failed to install VEH");
        std::process::exit(2);
    };

    let probe_specs = [
        ("VMREAD", 3, probe_vmread as unsafe fn()),
        ("VMWRITE", 3, probe_vmwrite as unsafe fn()),
        ("VMLAUNCH", 3, probe_vmlaunch as unsafe fn()),
        ("VMRESUME", 3, probe_vmresume as unsafe fn()),
        ("VMXOFF", 3, probe_vmxoff as unsafe fn()),
        ("VMCALL", 3, probe_vmcall_with_token as unsafe fn()),
        ("XSETBV", 3, probe_xsetbv_same_value as unsafe fn()),
        ("ENCLS", 3, probe_encls as unsafe fn()),
        ("ENCLV", 3, probe_enclv as unsafe fn()),
        ("INVD", 2, probe_invd as unsafe fn()),
        ("WBINVD", 2, probe_wbinvd as unsafe fn()),
        ("RDMSR", 2, probe_out_of_range_rdmsr as unsafe fn()),
        ("WRMSR", 2, probe_out_of_range_wrmsr as unsafe fn()),
    ];

    let mut ok = true;
    let mut ran = 0usize;
    for (name, skip_len, probe_fn) in probe_specs {
        if only
            .as_deref()
            .is_some_and(|filter| !name.eq_ignore_ascii_case(filter))
        {
            continue;
        }
        ran += 1;
        println!("  probing {}...", name);
        let probe = run_probe(name, skip_len, probe_fn);
        println!(
            "  {:<8} hit={} code={:#010x}",
            probe.name, probe.hit, probe.exception_code
        );

        if !probe.hit {
            ok = false;
        }
        if matches!(
            probe.name,
            "VMREAD"
                | "VMWRITE"
                | "VMLAUNCH"
                | "VMRESUME"
                | "VMXOFF"
                | "VMCALL"
                | "ENCLS"
                | "ENCLV"
        ) && probe.exception_code != EXCEPTION_ILLEGAL_INSTRUCTION
        {
            ok = false;
        }
    }

    if ran == 0 {
        println!("[-] no matching probe selected");
        std::process::exit(2);
    }

    if ok {
        println!("[+] user-mode probe behavior OK");
    } else {
        println!("[-] user-mode probe behavior failed");
        std::process::exit(1);
    }
}
