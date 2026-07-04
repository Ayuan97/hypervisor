use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

const COM2_DATA: u16 = 0x2f8;
const COM2_LSR: u16 = 0x2fd;

static TRACE_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "debug-log")]
unsafe fn com2_putb(b: u8) {
    use core::arch::asm;
    for _ in 0..10_000u32 {
        let status: u8;
        asm!("in al, dx", out("al") status, in("dx") COM2_LSR, options(nomem, nostack, preserves_flags));
        if status & 0x20 != 0 {
            asm!("out dx, al", in("al") b, in("dx") COM2_DATA, options(nomem, nostack, preserves_flags));
            return;
        }
    }
}

#[cfg(feature = "debug-log")]
fn emit(s: &str) {
    for &b in s.as_bytes() {
        unsafe { com2_putb(b) };
    }
}

#[cfg(feature = "debug-log")]
fn emit_hex(val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    emit("0x");
    let mut started = false;
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xf) as usize;
        if nibble != 0 || started || i == 0 {
            started = true;
            unsafe { com2_putb(HEX[nibble]) };
        }
    }
}

#[cfg(feature = "debug-log")]
fn emit_dec(val: u64) {
    if val == 0 {
        unsafe { com2_putb(b'0') };
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos = 20;
    let mut v = val;
    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    for &b in &buf[pos..] {
        unsafe { com2_putb(b) };
    }
}

#[cfg(feature = "debug-log")]
pub fn trace(msg: &str) {
    let seq = TRACE_SEQ.fetch_add(1, Relaxed);
    emit("[HV ");
    emit_dec(seq);
    emit("] ");
    emit(msg);
    emit("\r\n");
}

#[cfg(feature = "debug-log")]
pub fn trace_val(tag: &str, val: u64) {
    let seq = TRACE_SEQ.fetch_add(1, Relaxed);
    emit("[HV ");
    emit_dec(seq);
    emit("] ");
    emit(tag);
    emit(" = ");
    emit_hex(val);
    emit("\r\n");
}

#[cfg(feature = "debug-log")]
pub fn trace_stage(stage: u64) {
    let seq = TRACE_SEQ.fetch_add(1, Relaxed);
    emit("[HV ");
    emit_dec(seq);
    emit("] stage ");
    emit_dec(stage);
    emit("\r\n");
}

#[cfg(feature = "debug-log")]
pub fn trace_vmexit(reason: u64, rip: u64) {
    let seq = TRACE_SEQ.fetch_add(1, Relaxed);
    emit("[HV ");
    emit_dec(seq);
    emit("] exit reason=");
    emit_dec(reason & 0xFFFF);
    emit(" rip=");
    emit_hex(rip);
    emit("\r\n");
}

#[cfg(not(feature = "debug-log"))]
#[inline(always)]
pub fn trace(_msg: &str) {}

#[cfg(not(feature = "debug-log"))]
#[inline(always)]
pub fn trace_val(_tag: &str, _val: u64) {}

#[cfg(not(feature = "debug-log"))]
#[inline(always)]
pub fn trace_stage(_stage: u64) {}

#[cfg(not(feature = "debug-log"))]
#[inline(always)]
pub fn trace_vmexit(_reason: u64, _rip: u64) {}
