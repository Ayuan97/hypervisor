fn main() {
    let terminal = std::env::var("HV_TERMINAL_CAPTURE").ok().as_deref() == Some("1");
    let cmos_only = std::env::var("HV_CMOS_CAPTURE_ONLY").ok().as_deref() == Some("1");
    if terminal && cmos_only {
        panic!("HV_TERMINAL_CAPTURE and HV_CMOS_CAPTURE_ONLY are mutually exclusive");
    }
    // Debug / isolation build flags only. Production features are not env-gated.
    println!("cargo:rerun-if-env-changed=HV_BOOT_STOP_STAGE");
    println!("cargo:rerun-if-env-changed=HV_TRANSPARENT");
    println!("cargo:rerun-if-env-changed=HV_MINIMAL");
    println!("cargo:rerun-if-env-changed=HV_NO_EPT");
    println!("cargo:rerun-if-env-changed=HV_SKIP_CPU");
    println!("cargo:rerun-if-env-changed=HV_MAX_CPUS");
    println!("cargo:rerun-if-env-changed=HV_USER_CLIENT_READS");
    println!("cargo:rerun-if-env-changed=HV_LOCAL_DIAG");
    println!("cargo:rerun-if-env-changed=HV_TERMINAL_CAPTURE");
    println!("cargo:rerun-if-env-changed=HV_CMOS_CAPTURE_ONLY");
    println!("cargo:rerun-if-env-changed=HV_LBR_SHADOW");
}
