// Host stack allocation for VM-exit handling
// Each vCPU needs its own stack (typically 0x6000 bytes)
//
// Reference: matrix-rs/hypervisor/src/intel/vmstack.rs
