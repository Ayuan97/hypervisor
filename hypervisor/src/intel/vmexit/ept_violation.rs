// EPT violation handler
//
// Triggered when guest accesses a page with insufficient EPT permissions
// Used for EPT hook read/execute separation:
//   - Read violation on execute-only page → swap to read-only + enable MTF
//   - Execute violation on read-only page → swap to execute-only
//
// Reference: matrix-rs/hypervisor/src/intel/vmexit/
