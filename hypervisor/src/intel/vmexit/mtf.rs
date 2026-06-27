// Monitor Trap Flag handler
//
// After single-stepping one guest instruction (post-read),
// switch EPT entry back to execute-only and disable MTF
//
// Reference: matrix-rs/hypervisor/src/intel/vmexit/
