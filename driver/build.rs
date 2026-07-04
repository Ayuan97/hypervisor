use std::path::PathBuf;

fn latest_windows_kit_version(root: &str) -> Option<PathBuf> {
    std::fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .unwrap_or(false)
        })
        .max()
}

fn main() -> Result<(), wdk_build::ConfigError> {
    println!("cargo:rerun-if-env-changed=HV_BOOT_STOP_STAGE");
    println!("cargo:rerun-if-changed=src/seh.c");

    let mut config = wdk_build::Config::from_env_auto()?;
    config.driver_config = wdk_build::DriverConfig::WDM();
    config.configure_binary_build();

    let kit_include_root = r"C:\Program Files (x86)\Windows Kits\10\Include";
    let kit_include = latest_windows_kit_version(kit_include_root);
    let mut seh = cc::Build::new();
    seh.file("src/seh.c")
        .warnings(false)
        .define("_AMD64_", None)
        .define("AMD64", None)
        .define("_KERNEL_MODE", None)
        .flag("/kernel")
        .flag("/GS-")
        .flag("/Zl");
    if let Some(include) = kit_include {
        seh.include(include.join("km"))
            .include(include.join("shared"))
            .include(include.join("ucrt"));
    }
    seh.compile("matrix_seh");

    Ok(())
}
