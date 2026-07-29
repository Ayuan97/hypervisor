//! A crate for managing hypervisor functionality, particularly focused on
//! Extended Page Tables (EPT) and Model-Specific Register (MSR) bitmaps.
//! Includes support for primary and optional secondary EPTs.

use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::{hooks::HookManager, paging::Ept},
            msr_bitmap::MsrBitmap,
        },
        utils::alloc::PhysicalAllocator,
    },
    alloc::boxed::Box,
    core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicBool, Ordering},
    },
};

const EPT_UPDATE_RETRIES: usize = 100_000;

/// Represents shared data structures for hypervisor operations.
///
/// This struct manages the MSR (Model-Specific Register) bitmap and Extended Page Tables (EPT)
/// for the hypervisor, enabling memory virtualization and control over certain processor features.
#[repr(C)]
pub struct SharedData {
    /// A bitmap for handling MSRs.
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    /// The primary Extended Page Table.
    primary_ept: UnsafeCell<Box<Ept, PhysicalAllocator>>,

    /// The pointer to the primary EPT (Extended Page Table Pointer).
    pub primary_eptp: u64,

    /// The secondary Extended Page Table.
    #[cfg(feature = "secondary-ept")]
    pub secondary_ept: Box<Ept, PhysicalAllocator>,

    /// The pointer to the secondary EPT.
    #[cfg(feature = "secondary-ept")]
    pub secondary_eptp: u64,

    /// The hook manager.
    pub hook_manager: Box<HookManager>,

    /// Serializes mutable primary-EPT updates originating from different
    /// VM-exit handlers. Read-only EPTP access remains lock-free.
    ept_update_lock: AtomicBool,
}

impl SharedData {
    /// Creates a new instance of `SharedData` with primary and optionally secondary EPTs.
    ///
    /// This function initializes the MSR bitmap and sets up the EPTs.
    ///
    /// # Arguments
    ///
    /// * `primary_ept`: The primary EPT to be used.
    /// * `secondary_ept`: The secondary EPT to be used if the feature is enabled.
    ///
    /// # Returns
    /// A result containing a boxed `SharedData` instance or an error of type `HypervisorError`.
    #[cfg(feature = "secondary-ept")]
    pub fn new(
        primary_ept: Box<Ept, PhysicalAllocator>,
        secondary_ept: Box<Ept, PhysicalAllocator>,
        hook_manager: Box<HookManager>,
    ) -> Result<Box<Self>, HypervisorError> {
        log::trace!("Initializing shared data");

        let primary_eptp = primary_ept.create_eptp_with_wb_and_4lvl_walk()?;
        let secondary_eptp = secondary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        let bitmap = MsrBitmap::new();
        //bitmap.hook_msr(IA32_EFER);

        Ok(Box::new(Self {
            msr_bitmap: { bitmap },
            primary_ept: UnsafeCell::new(primary_ept),
            primary_eptp,
            secondary_ept,
            secondary_eptp,
            hook_manager,
            ept_update_lock: AtomicBool::new(false),
        }))
    }

    /// Creates a new instance of `SharedData` with primary EPTs.
    ///
    /// This function initializes the MSR bitmap and sets up the EPTs.
    ///
    /// # Arguments
    ///
    /// * `primary_ept`: The primary EPT to be used.
    ///
    /// # Returns
    /// A result containing a boxed `SharedData` instance or an error of type `HypervisorError`.
    #[cfg(not(feature = "secondary-ept"))]
    pub fn new(
        primary_ept: Box<Ept, PhysicalAllocator>,
        hook_manager: Box<HookManager>,
    ) -> Result<Box<Self>, HypervisorError> {
        log::trace!("Initializing shared data");

        let primary_eptp = primary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        let bitmap = MsrBitmap::new();

        Ok(Box::new(Self {
            msr_bitmap: { bitmap },
            primary_ept: UnsafeCell::new(primary_ept),
            primary_eptp,
            hook_manager,
            ept_update_lock: AtomicBool::new(false),
        }))
    }

    /// Run a bounded, serialized update against the shared primary EPT.
    ///
    /// VM-exit handlers must not hold a mutable reference to the global EPT
    /// without this guard: more than one logical CPU can process a cloak or
    /// bugcheck-hook transition at the same time.
    pub fn with_primary_ept_mut<R>(&self, update: impl FnOnce(&mut Ept) -> R) -> Option<R> {
        for _ in 0..EPT_UPDATE_RETRIES {
            if self
                .ept_update_lock
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let result = update(unsafe { &mut **self.primary_ept.get() });
                self.ept_update_lock.store(false, Ordering::Release);
                return Some(result);
            }
            core::hint::spin_loop();
        }
        None
    }
}
