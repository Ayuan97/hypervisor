// VMCALL handler - communication channel with usermode (game_overlay)
//
// Protocol:
//   RAX = magic (authentication)
//   RCX = command ID
//   RDX = argument 1 (typically physical address)
//   R8  = argument 2 (typically size)
//   R9  = argument 3 (typically output buffer pointer)
//
// Commands:
//   0x01 = PING           → return magic in RAX (presence check)
//   0x10 = READ_PHYS      → read physical memory at RDX, len R8, into R9
//   0x11 = WRITE_PHYS     → write to physical memory at RDX, len R8, from R9
//   0x12 = TRANSLATE_VA   → CR3 in RDX, VA in R8 → return PA in RAX
//   0x20 = EPT_HOOK       → set EPT hook at physical page RDX
//   0x21 = EPT_UNHOOK     → remove EPT hook at physical page RDX
//
// Security: validate magic value before executing any command
// Invalid VMCALL (no magic match) → inject #UD to guest

pub const VMCALL_MAGIC: u64 = 0x4879_7065_7256_4D00; // "HyperVM\0"

pub const CMD_PING: u64 = 0x01;
pub const CMD_READ_PHYS: u64 = 0x10;
pub const CMD_WRITE_PHYS: u64 = 0x11;
pub const CMD_TRANSLATE_VA: u64 = 0x12;
pub const CMD_EPT_HOOK: u64 = 0x20;
pub const CMD_EPT_UNHOOK: u64 = 0x21;
