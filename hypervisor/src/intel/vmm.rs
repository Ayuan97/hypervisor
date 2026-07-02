//! The main module for the hypervisor.

use {
    crate::{
        error::HypervisorError,
        intel::{
            diag,
            ept::{hooks::HookManager, paging::Ept},
            shared_data::SharedData,
            vcpu::Vcpu,
        },
        utils::{
            alloc::PhysicalAllocator,
            processor::{processor_count, ProcessorExecutor},
        },
    },
    alloc::{boxed::Box, vec::Vec},
    core::mem::ManuallyDrop,
};

const NO_SKIP_CPU: u32 = u32::MAX;
const SKIP_CPU_INDEX: u32 = parse_skip_cpu(option_env!("HV_SKIP_CPU"));

#[derive(Default)]
pub struct HypervisorBuilder {
    /// The primary extended page table.
    primary_ept: Option<Box<Ept, PhysicalAllocator>>,

    #[cfg(feature = "secondary-ept")]
    /// The secondary extended page table.
    secondary_ept: Option<Box<Ept, PhysicalAllocator>>,

    /// The hook manager.
    hook_manager: Option<Box<HookManager>>,
}

impl HypervisorBuilder {
    /// Creates a new HypervisorBuilder instance.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if hypervisor initialization was successful, or `Err` if there was an error.
    pub fn build(self) -> Result<Hypervisor, HypervisorError> {
        log::debug!("Building hypervisor");

        Hypervisor::check_supported_cpu()?;

        let mut processors: Vec<Vcpu> = Vec::new();

        for i in 0..processor_count() {
            processors.push(Vcpu::new(i)?);
        }

        log::info!("Found {} processors", processors.len());

        let hook_manager = self
            .hook_manager
            .ok_or(HypervisorError::HookManagerNotProvided)?;

        let primary_ept = self
            .primary_ept
            .ok_or(HypervisorError::PrimaryEPTNotProvided)?;

        #[cfg(not(feature = "secondary-ept"))]
        let shared_data = SharedData::new(primary_ept, hook_manager)?;

        #[cfg(feature = "secondary-ept")]
        let shared_data = {
            let secondary_ept = self
                .secondary_ept
                .ok_or(HypervisorError::SecondaryEPTNotProvided)?;

            SharedData::new(primary_ept, secondary_ept, hook_manager)?
        };

        Ok(Hypervisor {
            processors: ManuallyDrop::new(processors),
            shared_data: ManuallyDrop::new(shared_data),
            devirtualized: true,
        })
    }

    pub fn primary_ept(mut self, ept: Box<Ept, PhysicalAllocator>) -> Self {
        self.primary_ept = Some(ept);
        self
    }

    #[cfg(feature = "secondary-ept")]
    pub fn secondary_ept(mut self, ept: Box<Ept, PhysicalAllocator>) -> Self {
        self.secondary_ept = Some(ept);
        self
    }

    pub fn hook_manager(mut self, hook_manager: Box<HookManager>) -> Self {
        self.hook_manager = Some(hook_manager);
        self
    }
}

/// The main struct representing the hypervisor.
pub struct Hypervisor {
    /// The processors to virtualize.
    processors: ManuallyDrop<Vec<Vcpu>>,

    /// The shared data between processors.
    shared_data: ManuallyDrop<Box<SharedData>>,

    /// Whether all processors are known to be outside VMX non-root operation.
    devirtualized: bool,
}

impl Hypervisor {
    /// Creates a new HypervisorBuilder instance.
    pub fn builder() -> HypervisorBuilder {
        HypervisorBuilder::default()
    }

    /// Virtualizes the system's processors.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the virtualization was successful, or `Err` if there was an error.
    pub fn virtualize_core(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Virtualizing processors");

        for processor in self.processors.iter_mut() {
            if cpu_virtualization_is_skipped(processor.id()) {
                log::warn!("Skipping virtualization for processor {}", processor.id());
                diag::boot_stage(330 + processor.id() as u64)?;
                continue;
            }

            diag::boot_stage(300 + processor.id() as u64)?;
            log::info!("hv stage 300 cpu={}", processor.id());
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                let _ = diag::boot_stage(390 + processor.id() as u64);
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            if let Err(error) = diag::boot_stage(310 + processor.id() as u64) {
                drop(executor);
                return Err(error);
            }
            self.devirtualized = false;
            processor.virtualize_cpu(self.shared_data.as_mut())?;
            if let Err(error) = diag::boot_stage(320 + processor.id() as u64) {
                drop(executor);
                return Err(error);
            }

            drop(executor);
        }

        Ok(())
    }

    /// Reverts the virtualization of the system's processors.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the devirtualization was successful, or `Err` if there was an error.
    pub fn devirtualize_system(&mut self) -> Result<(), HypervisorError> {
        log::trace!("Devirtualizing processors");

        if self.devirtualized {
            return Ok(());
        }

        for processor in self.processors.iter_mut() {
            diag::set_boot_stage(800 + processor.id() as u64);
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                diag::set_boot_stage(890 + processor.id() as u64);
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            processor.devirtualize_cpu()?;
            diag::set_boot_stage(820 + processor.id() as u64);

            drop(executor);
        }

        self.devirtualized = true;

        Ok(())
    }

    /// Check if the CPU is supported.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the CPU is supported, or `Err` if it's not.
    fn check_supported_cpu() -> Result<(), HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.6 DISCOVERING SUPPORT FOR VMX */
        Self::has_intel_cpu()?;
        log::info!("CPU is Intel");

        Self::has_vmx_support()?;
        log::info!("Virtual Machine Extension (VMX) technology is supported");

        Self::has_mtrr()?;
        log::info!("Memory Type Range Registers (MTRRs) are supported");

        Ok(())
    }

    /// Check to see if CPU is Intel (“GenuineIntel”).
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the CPU is Intel, or `Err` if it's not.
    fn has_intel_cpu() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(vi) = cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return Ok(());
            }
        }
        Err(HypervisorError::CPUUnsupported)
    }

    /// Check processor support for Virtual Machine Extension (VMX) technology.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if VMX technology is supported, or `Err` if it's not.
    fn has_vmx_support() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        Err(HypervisorError::VMXUnsupported)
    }

    /// Check processor support for Memory Type Range Registers (MTRRs).
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if MTRRs are supported, or `Err` if it's not.
    fn has_mtrr() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_mtrr() {
                return Ok(());
            }
        }
        Err(HypervisorError::MTRRUnsupported)
    }
}

const fn parse_skip_cpu(value: Option<&str>) -> u32 {
    let Some(value) = value else {
        return NO_SKIP_CPU;
    };

    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return NO_SKIP_CPU;
    }

    let mut i = 0;
    let mut parsed = 0u32;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte < b'0' || byte > b'9' {
            return NO_SKIP_CPU;
        }
        parsed = parsed
            .saturating_mul(10)
            .saturating_add((byte - b'0') as u32);
        i += 1;
    }
    parsed
}

fn cpu_virtualization_is_skipped(index: u32) -> bool {
    cpu_virtualization_is_skipped_with_config(SKIP_CPU_INDEX, index)
}

fn cpu_virtualization_is_skipped_with_config(skip_cpu: u32, index: u32) -> bool {
    skip_cpu != NO_SKIP_CPU && skip_cpu == index
}

fn drop_should_release_owned_resources(devirtualized: bool, cleanup_succeeded: bool) -> bool {
    devirtualized || cleanup_succeeded
}

impl Drop for Hypervisor {
    /// Handles the dropping of the `Hypervisor` instance.
    ///
    /// When a `Hypervisor` instance goes out of scope or is explicitly dropped,
    /// this method attempts to devirtualize the system and logs the result.
    fn drop(&mut self) {
        let was_devirtualized = self.devirtualized;
        let cleanup_succeeded = if was_devirtualized {
            true
        } else {
            match self.devirtualize_system() {
                Ok(_) => {
                    log::trace!("Devirtualized successfully!");
                    true
                }
                Err(err) => {
                    log::error!(
                        "Failed to devirtualize {}; leaking hypervisor resources",
                        err
                    );
                    false
                }
            }
        };

        if drop_should_release_owned_resources(was_devirtualized, cleanup_succeeded) {
            unsafe {
                crate::utils::nt::IDENTITY_CR3 = 0;
                ManuallyDrop::drop(&mut self.processors);
                ManuallyDrop::drop(&mut self.shared_data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_releases_owned_resources_only_after_successful_cleanup() {
        assert!(drop_should_release_owned_resources(true, false));
        assert!(drop_should_release_owned_resources(false, true));
        assert!(!drop_should_release_owned_resources(false, false));
    }

    #[test]
    fn skip_cpu_parser_accepts_decimal_only() {
        assert_eq!(parse_skip_cpu(None), NO_SKIP_CPU);
        assert_eq!(parse_skip_cpu(Some("")), NO_SKIP_CPU);
        assert_eq!(parse_skip_cpu(Some("8")), 8);
        assert_eq!(parse_skip_cpu(Some("8x")), NO_SKIP_CPU);
    }

    #[test]
    fn skip_cpu_matches_only_selected_processor() {
        assert!(!cpu_virtualization_is_skipped_with_config(NO_SKIP_CPU, 8));
        assert!(cpu_virtualization_is_skipped_with_config(8, 8));
        assert!(!cpu_virtualization_is_skipped_with_config(8, 7));
    }
}
