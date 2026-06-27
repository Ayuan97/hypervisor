#[derive(Debug, Clone, Copy)]
pub enum HvError {
    VmxNotSupported,
    EptNotSupported,
    VmxOnFailed,
    VmClearFailed,
    VmPtrLoadFailed,
    VmWriteFailed,
    VmLaunchFailed,
    VmResumeFailed,
    EptMisconfiguration,
    InvalidVmCallId,
    MemoryAllocationFailed,
}
