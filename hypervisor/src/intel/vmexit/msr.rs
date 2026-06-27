// MSR read/write VM-exit handler
//
// Anti-detection:
// - IA32_EFER: EAC checks SCE bit ~30min into gameplay
// - Don't modify EFER unless actually hooking syscalls via EFER method
// - IA32_VMX_* MSRs: hide VMX capability if queried
