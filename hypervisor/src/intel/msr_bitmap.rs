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
const IA32_EFER: u32 = 0xC000_0080;
const IA32_MPERF: u32 = 0xE7;
const IA32_APERF: u32 = 0xE8;
const IA32_DEBUGCTL: u32 = 0x1D9;
const IA32_LASTBRANCH_TOS: u32 = 0x1C9;
// Intel SDM Vol 4: LASTBRANCH_FROM_i = 0x680 + i (32 entries), LASTBRANCH_TO_i = 0x6C0 + i (32 entries).
// The gap 0x6A0-0x6BF holds LASTBRANCH_INFO_i / reserved — NOT the TO stack. Older code assumed
// the two ranges were contiguous; correct intercept is two disjoint blocks.
const IA32_LBR_FROM_START: u32 = 0x680;
const IA32_LBR_FROM_END: u32 = 0x69F;
const IA32_LBR_TO_START: u32 = 0x6C0;
const IA32_LBR_TO_END: u32 = 0x6DF;

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

        // IA32_TSC_AUX — write always intercepted; read only when the shadow
        // is enabled at build time (HV_ENABLE_TSC_AUX_SHADOW=1).
        //
        // Writes must always be intercepted: host IDT handlers use rdtscp for
        // per-CPU indexing, so a guest WRMSR to physical MSR would corrupt
        // host's index. Absorbed by `msr.rs`.
        //
        // Reads: with the shadow enabled, we return the shadow so a
        // wrmsr-then-rdmsr probe (an EAC fingerprint) is consistent with bare
        // metal. Disabled by default 2026-07-17 after a BSOD 0x1E during
        // isolation testing — see `msr.rs::tsc_aux_shadow_enabled`.
        set_msr_bitmap_bit(&mut self.write_high_msrs, IA32_TSC_AUX);
        if option_env!("HV_ENABLE_TSC_AUX_SHADOW").map_or(false, |v| v == "1") {
            set_msr_bitmap_bit(&mut self.read_high_msrs, IA32_TSC_AUX);
        }

        // ---- P2 stealth interception (secret.club EAC detection vectors) ----

        // IA32_EFER (0xC000_0080). Falls in the high range (0xC0000000-0xC0001FFF).
        // Read intercept lets us hand back a consistent EFER value and count how
        // often EAC queries it; write intercept ensures guest cannot toggle SCE
        // without our knowledge.
        let efer_low = IA32_EFER - 0xC000_0000;
        set_msr_bitmap_bit(&mut self.read_high_msrs, efer_low);
        set_msr_bitmap_bit(&mut self.write_high_msrs, efer_low);

        // APERF / MPERF — NOT intercepted.
        //
        // The old comment claimed "reads pass through so ratio stays close
        // to bare metal (our VM-exit rate is very low anyway)". Empirically
        // false: Windows scheduler reads both on every tick × 24 logical
        // processors × 250 Hz ≈ 6 000 baseline exits/sec, and under a real
        // workload (Rust + EAC) that scaled to millions/sec with the
        // handler adding ~200 ns each — a big chunk of the exit-rate
        // storm that repeatedly crashed the box after the C-state clamps
        // pushed idle exits on top. KVM ran into the same problem and
        // fixed it by leaving these MSRs passthrough (LWN 998994). We do
        // the same. Diagnostic APERF_READ_COUNT / MPERF_READ_COUNT stop
        // incrementing but the freeze-relevant signal (Rust/EAC caused
        // us to hit ratios wildly outside bare metal) can be recovered
        // by turning the intercept back on for a single measurement run
        // if we ever need it again.

        // MSR_PKG_CST_CONFIG_CONTROL (0xE2) — NOT intercepted.
        //
        // Was added 2026-07-12 (5668ac1) to shadow a "limit = C1" read back
        // to the guest, alongside a swallowed write. In practice the write
        // path is unreachable because BIOS locks the MSR (CFG_LOCK bit 15)
        // long before we boot, so the intercept only ever changed READS —
        // and lying to the Windows power-management driver about the deepest
        // supported C-state turned out to correlate with the regression from
        // "5-hour stable HV+EAC session" to "freezes inside 2 minutes" on
        // the same day. Removing the intercept restores what the driver
        // actually sees on bare metal, without giving up any real
        // stealth (0xE2's value on this box is 0-limit either way).
        //
        // IA32_DEBUGCTL (0x1D9) + LBR TOS + LBR stack (0x680-0x6BF). Intercept
        // both directions so guest cannot observe host branches leaking into
        // LBR after a VM-exit.
        set_msr_bitmap_bit(&mut self.read_low_msrs, IA32_DEBUGCTL);
        set_msr_bitmap_bit(&mut self.write_low_msrs, IA32_DEBUGCTL);
        set_msr_bitmap_bit(&mut self.read_low_msrs, IA32_LASTBRANCH_TOS);
        set_msr_bitmap_bit(&mut self.write_low_msrs, IA32_LASTBRANCH_TOS);
        for msr in IA32_LBR_FROM_START..=IA32_LBR_FROM_END {
            set_msr_bitmap_bit(&mut self.read_low_msrs, msr);
            set_msr_bitmap_bit(&mut self.write_low_msrs, msr);
        }
        for msr in IA32_LBR_TO_START..=IA32_LBR_TO_END {
            set_msr_bitmap_bit(&mut self.read_low_msrs, msr);
            set_msr_bitmap_bit(&mut self.write_low_msrs, msr);
        }
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

    #[test]
    fn efer_is_intercepted_in_high_range() {
        let mut bitmap = empty_bitmap();
        bitmap.intercept_vmx_msrs();

        let efer_low = IA32_EFER - 0xC000_0000;
        assert!(msr_bitmap_bit_is_set(&bitmap.read_high_msrs, efer_low));
        assert!(msr_bitmap_bit_is_set(&bitmap.write_high_msrs, efer_low));
    }

    #[test]
    fn aperf_and_mperf_are_never_intercepted() {
        // Windows scheduler polls both MSRs on every tick per logical CPU;
        // intercepting them scaled to millions of exits/sec under EAC load.
        // Both directions must stay pass-through — see msr_bitmap.rs comment.
        let mut bitmap = empty_bitmap();
        bitmap.intercept_vmx_msrs();

        assert!(!msr_bitmap_bit_is_set(&bitmap.read_low_msrs, IA32_MPERF));
        assert!(!msr_bitmap_bit_is_set(&bitmap.read_low_msrs, IA32_APERF));
        assert!(!msr_bitmap_bit_is_set(&bitmap.write_low_msrs, IA32_MPERF));
        assert!(!msr_bitmap_bit_is_set(&bitmap.write_low_msrs, IA32_APERF));
    }

    #[test]
    fn pkg_cst_config_control_is_not_intercepted() {
        // 0xE2 shadow was linked to the 5h→2min regression on 2026-07-12
        // and removed. The intercept must not come back accidentally.
        let mut bitmap = empty_bitmap();
        bitmap.intercept_vmx_msrs();

        assert!(!msr_bitmap_bit_is_set(&bitmap.read_low_msrs, 0xE2));
        assert!(!msr_bitmap_bit_is_set(&bitmap.write_low_msrs, 0xE2));
    }

    #[test]
    fn debugctl_and_lbr_stack_are_intercepted_both_ways() {
        let mut bitmap = empty_bitmap();
        bitmap.intercept_vmx_msrs();

        for msr in [
            IA32_DEBUGCTL,
            IA32_LASTBRANCH_TOS,
            IA32_LBR_FROM_START,
            IA32_LBR_FROM_END,
            IA32_LBR_TO_START,
            IA32_LBR_TO_END,
        ] {
            assert!(msr_bitmap_bit_is_set(&bitmap.read_low_msrs, msr), "read {:#x}", msr);
            assert!(msr_bitmap_bit_is_set(&bitmap.write_low_msrs, msr), "write {:#x}", msr);
        }
        // The gap 0x6A0-0x6BF (LASTBRANCH_INFO / reserved) is deliberately NOT intercepted.
        assert!(!msr_bitmap_bit_is_set(&bitmap.read_low_msrs, 0x6A0));
        assert!(!msr_bitmap_bit_is_set(&bitmap.read_low_msrs, 0x6BF));
        // Immediately past the TO block also must not leak.
        assert!(!msr_bitmap_bit_is_set(&bitmap.read_low_msrs, IA32_LBR_TO_END + 1));
    }
}
