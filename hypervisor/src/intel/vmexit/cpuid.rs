// CPUID VM-exit handler
//
// Anti-detection:
// - leaf 1, ECX bit 31: clear hypervisor present flag
// - leaf 0x40000000: don't expose hypervisor vendor string
// - Forward all other leaves to real CPUID
//
// Reference: Secret Club article on system emulation detection
// EAC checks: VMREAD instruction (inject #UD), CPUID hypervisor bit
