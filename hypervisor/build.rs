fn main() {
    println!("cargo:rerun-if-env-changed=HV_BOOT_STOP_STAGE");
    println!("cargo:rerun-if-env-changed=HV_ENABLE_PT_CONCEAL");
    println!("cargo:rerun-if-env-changed=HV_PT_CONCEAL_MASK");
}
