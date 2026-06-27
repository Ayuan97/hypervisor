// RDTSC / RDTSCP VM-exit handler
//
// Anti-detection: compensate VM-exit overhead
// Track cumulative VM-exit cycles, subtract from RDTSC return value
// so timing measurements from guest appear consistent
//
// EAC/BattlEye use: RDTSC → CPUID → RDTSC timing attack
// If delta is >> expected, hypervisor presence is inferred
