// EPT hook management
//
// Hook workflow:
// 1. Allocate shadow page, copy original, patch with hook code
// 2. Split target 2MB page into 512 x 4KB pages
// 3. Set target 4KB PTE to execute-only → shadow page
// 4. On EPT violation (read):
//    - Switch PTE to read-only → original page
//    - Enable MTF (Monitor Trap Flag)
// 5. On MTF exit:
//    - Switch PTE back to execute-only → shadow page
//    - Disable MTF
//
// Reference: matrix-rs/hypervisor/src/intel/ept/hooks.rs (if feature "secondary-ept")
