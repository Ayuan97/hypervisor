fn main() {
    // Debug / isolation build flags only. Production features are not env-gated.
    println!("cargo:rerun-if-env-changed=HV_BOOT_STOP_STAGE");
    println!("cargo:rerun-if-env-changed=HV_TRANSPARENT");
    println!("cargo:rerun-if-env-changed=HV_MINIMAL");
    println!("cargo:rerun-if-env-changed=HV_NO_EPT");
    println!("cargo:rerun-if-env-changed=HV_SKIP_CPU");
    println!("cargo:rerun-if-env-changed=HV_USER_CLIENT_READS");
    println!("cargo:rerun-if-env-changed=HV_LOCAL_DIAG");
}
