use super::vmcs::Vmcs;
use crate::error::HypervisorError;

/// Enable VMX operation.
pub fn vmxon(vmxon_region: u64) -> Result<(), HypervisorError> {
    unsafe { x86::bits64::vmx::vmxon(vmxon_region) }.map_err(|_| HypervisorError::VMXONFailed)
}

/// Disable VMX operation.
pub fn vmxoff() -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmxoff() } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMXOFFFailed),
    }
}

/// Clear VMCS.
pub fn vmclear(vmcs_region: u64) -> Result<(), HypervisorError> {
    unsafe { x86::bits64::vmx::vmclear(vmcs_region) }.map_err(|_| HypervisorError::VMCLEARFailed)
}

/// Load current VMCS pointer.
pub fn vmptrld(vmcs_region: u64) -> Result<(), HypervisorError> {
    unsafe { x86::bits64::vmx::vmptrld(vmcs_region) }.map_err(|_| HypervisorError::VMPTRLDFailed)
}

/// Return current VMCS pointer.
#[allow(dead_code)]
pub fn vmptrst() -> *const Vmcs {
    unsafe { x86::bits64::vmx::vmptrst().unwrap_or(0) as *const Vmcs }
}

/// Read a specified field from a VMCS.
pub fn vmread(field: u32) -> u64 {
    match vmread_checked(field) {
        Ok(value) => value,
        Err(_) => {
            log::error!("VMREAD failed for field {:#x}", field);
            0
        }
    }
}

/// Read a specified VMCS field and surface the VM instruction failure.
pub fn vmread_checked(field: u32) -> Result<u64, HypervisorError> {
    unsafe { x86::bits64::vmx::vmread(field) }.map_err(|_| HypervisorError::VMREADFailed)
}

/// Write to a specified field in a VMCS.
pub fn vmwrite<T: Into<u64>>(field: u32, val: T)
where
    u64: From<T>,
{
    if vmwrite_checked(field, val).is_err() {
        log::error!("VMWRITE failed for field {:#x}", field);
    }
}

/// Write to a specified VMCS field and surface the VM instruction failure.
pub fn vmwrite_checked<T: Into<u64>>(field: u32, val: T) -> Result<(), HypervisorError>
where
    u64: From<T>,
{
    unsafe { x86::bits64::vmx::vmwrite(field, u64::from(val)) }
        .map_err(|_| HypervisorError::VMWRITEFailed)
}
