//! This module provides utilities and structures to manage the MSR Bitmap in VMX.
//! The MSR Bitmap is used to control the behavior of RDMSR and WRMSR instructions
//! in a virtualized environment.

use {
    crate::utils::alloc::PhysicalAllocator,
    alloc::boxed::Box,
    core::mem::MaybeUninit,
    wdk_sys::{
        ntddk::{RtlClearAllBits, RtlInitializeBitMap},
        RTL_BITMAP,
    },
};

const IA32_VMX_MSR_START: u32 = 0x480;
const IA32_VMX_MSR_END: u32 = 0x491;
const IA32_FEATURE_CONTROL_MSR: u32 = 0x3a;
const IA32_SGXLEPUBKEYHASH_MSR_START: u32 = 0x8c;
const IA32_SGXLEPUBKEYHASH_MSR_END: u32 = 0x8f;
const IA32_RTIT_OUTPUT_BASE_MSR: u32 = 0x560;
const IA32_RTIT_OUTPUT_MASK_PTRS_MSR: u32 = 0x561;
const IA32_RTIT_CTL_MSR: u32 = 0x570;
const IA32_RTIT_STATUS_MSR: u32 = 0x571;
const IA32_RTIT_CR3_MATCH_MSR: u32 = 0x572;
const IA32_RTIT_ADDR_MSR_START: u32 = 0x580;
const IA32_RTIT_ADDR_MSR_END: u32 = 0x58f;
const IA32_TSC_AUX: u32 = 0x103;

/// Represents the MSR Bitmap structure used in VMX.
///
/// In processors that support the 1-setting of the “use MSR bitmaps” VM-execution control,
/// the VM-execution control fields include the 64-bit physical address of four contiguous
/// MSR bitmaps, which are each 1-KByte in size.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.6.9 MSR-Bitmap Address
#[repr(C, align(4096))]
pub struct MsrBitmap {
    /// Read bitmap for low MSRs. Contains one bit for each MSR address in the range 00000000H to 00001FFFH.
    /// Determines whether an execution of RDMSR applied to that MSR causes a VM exit.
    pub read_low_msrs: [u8; 0x400],

    /// Read bitmap for high MSRs. Contains one bit for each MSR address in the range C0000000H to C0001FFFH.
    /// Determines whether an execution of RDMSR applied to that MSR causes a VM exit.
    pub read_high_msrs: [u8; 0x400],

    /// Write bitmap for low MSRs. Contains one bit for each MSR address in the range 00000000H to 00001FFFH.
    /// Determines whether an execution of WRMSR applied to that MSR causes a VM exit.
    pub write_low_msrs: [u8; 0x400],

    /// Write bitmap for high MSRs. Contains one bit for each MSR address in the range C0000000H to C0001FFFH.
    /// Determines whether an execution of WRMSR applied to that MSR causes a VM exit.
    pub write_high_msrs: [u8; 0x400],
}

impl MsrBitmap {
    /// Sets up the MSR Bitmap.
    ///
    /// # Returns
    /// * A `Result` indicating the success or failure of the setup process.
    pub fn new() -> Box<MsrBitmap, PhysicalAllocator> {
        log::trace!("Setting up MSR Bitmap");

        let instance = Self {
            read_low_msrs: [0; 0x400],
            read_high_msrs: [0; 0x400],
            write_low_msrs: [0; 0x400],
            write_high_msrs: [0; 0x400],
        };
        let mut instance = Box::<Self, PhysicalAllocator>::new_in(instance, PhysicalAllocator);

        log::trace!("Initializing MSR Bitmap");

        Self::initialize_bitmap(instance.as_mut() as *mut _ as _);
        instance.intercept_vmx_msrs();

        log::trace!("MSR Bitmap setup successfully!");

        instance
    }

    /// Initializes the MSR Bitmap.
    ///
    /// # Arguments
    /// * `bitmap_ptr` - The virtual address of the MSR Bitmap.
    fn initialize_bitmap(bitmap_ptr: *mut u64) {
        let mut bitmap_header: MaybeUninit<RTL_BITMAP> = MaybeUninit::uninit();
        let bitmap_header_ptr = bitmap_header.as_mut_ptr() as *mut _;

        unsafe {
            RtlInitializeBitMap(
                bitmap_header_ptr as _,
                bitmap_ptr as _,
                msr_bitmap_size_bits(),
            )
        }
        unsafe { RtlClearAllBits(bitmap_header_ptr as _) }
    }

    fn intercept_vmx_msrs(&mut self) {
        set_msr_bitmap_bit(&mut self.read_low_msrs, IA32_FEATURE_CONTROL_MSR);
        set_msr_bitmap_bit(&mut self.write_low_msrs, IA32_FEATURE_CONTROL_MSR);

        for msr in IA32_SGXLEPUBKEYHASH_MSR_START..=IA32_SGXLEPUBKEYHASH_MSR_END {
            set_msr_bitmap_bit(&mut self.read_low_msrs, msr);
            set_msr_bitmap_bit(&mut self.write_low_msrs, msr);
        }

        for msr in IA32_VMX_MSR_START..=IA32_VMX_MSR_END {
            set_msr_bitmap_bit(&mut self.read_low_msrs, msr);
            set_msr_bitmap_bit(&mut self.write_low_msrs, msr);
        }

        for msr in [
            IA32_RTIT_OUTPUT_BASE_MSR,
            IA32_RTIT_OUTPUT_MASK_PTRS_MSR,
            IA32_RTIT_CTL_MSR,
            IA32_RTIT_STATUS_MSR,
            IA32_RTIT_CR3_MATCH_MSR,
        ] {
            set_msr_bitmap_bit(&mut self.read_low_msrs, msr);
            set_msr_bitmap_bit(&mut self.write_low_msrs, msr);
        }

        for msr in IA32_RTIT_ADDR_MSR_START..=IA32_RTIT_ADDR_MSR_END {
            set_msr_bitmap_bit(&mut self.read_low_msrs, msr);
            set_msr_bitmap_bit(&mut self.write_low_msrs, msr);
        }

        // Intercept writes to IA32_TSC_AUX — host IDT handlers use rdtscp
        // for per-CPU indexing; a guest WRMSR would corrupt that index.
        set_msr_bitmap_bit(&mut self.write_high_msrs, IA32_TSC_AUX);
    }
}

fn set_msr_bitmap_bit(bitmap: &mut [u8], msr: u32) {
    let bit = msr as usize;
    let byte_index = bit / 8;
    if byte_index >= bitmap.len() {
        return;
    }
    bitmap[byte_index] |= 1u8 << (bit & 7);
}

fn msr_bitmap_size_bits() -> u32 {
    (core::mem::size_of::<MsrBitmap>() * 8) as u32
}

#[cfg(test)]
fn msr_bitmap_bit_is_set(bitmap: &[u8], msr: u32) -> bool {
    let bit = msr as usize;
    let byte_index = bit / 8;
    byte_index < bitmap.len() && (bitmap[byte_index] & (1u8 << (bit & 7))) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_bitmap() -> MsrBitmap {
        MsrBitmap {
            read_low_msrs: [0; 0x400],
            read_high_msrs: [0; 0x400],
            write_low_msrs: [0; 0x400],
            write_high_msrs: [0; 0x400],
        }
    }

    #[test]
    fn vmx_msrs_are_intercepted_for_reads_and_writes() {
        let mut bitmap = empty_bitmap();

        bitmap.intercept_vmx_msrs();

        assert!(msr_bitmap_bit_is_set(&bitmap.read_low_msrs, 0x480));
        assert!(msr_bitmap_bit_is_set(&bitmap.write_low_msrs, 0x480));
        assert!(msr_bitmap_bit_is_set(&bitmap.read_low_msrs, 0x491));
        assert!(msr_bitmap_bit_is_set(&bitmap.write_low_msrs, 0x491));
        assert!(msr_bitmap_bit_is_set(&bitmap.read_low_msrs, 0x3a));
        assert!(msr_bitmap_bit_is_set(&bitmap.write_low_msrs, 0x3a));
        assert!(msr_bitmap_bit_is_set(&bitmap.read_low_msrs, 0x8c));
        assert!(msr_bitmap_bit_is_set(&bitmap.write_low_msrs, 0x8f));
        assert!(!msr_bitmap_bit_is_set(&bitmap.read_low_msrs, 0x47f));
        assert!(!msr_bitmap_bit_is_set(&bitmap.write_low_msrs, 0x492));
    }

    #[test]
    fn tsc_aux_write_is_intercepted_but_read_passes_through() {
        let mut bitmap = empty_bitmap();

        bitmap.intercept_vmx_msrs();

        assert!(msr_bitmap_bit_is_set(&bitmap.write_high_msrs, IA32_TSC_AUX));
        assert!(!msr_bitmap_bit_is_set(&bitmap.read_high_msrs, IA32_TSC_AUX));
    }

    #[test]
    fn intel_pt_msrs_are_intercepted_for_reads_and_writes() {
        let mut bitmap = empty_bitmap();

        bitmap.intercept_vmx_msrs();

        for msr in [0x560, 0x561, 0x570, 0x571, 0x572, 0x580, 0x58f] {
            assert!(msr_bitmap_bit_is_set(&bitmap.read_low_msrs, msr));
            assert!(msr_bitmap_bit_is_set(&bitmap.write_low_msrs, msr));
        }
    }

    #[test]
    fn rtl_bitmap_size_covers_the_full_msr_bitmap_buffer() {
        assert_eq!(
            msr_bitmap_size_bits(),
            (core::mem::size_of::<MsrBitmap>() * 8) as u32
        );
    }
}
